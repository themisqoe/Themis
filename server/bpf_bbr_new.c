#include <linux/bpf.h>
#include <linux/stddef.h>
#include <linux/tcp.h>
#include <stdio.h>
#include <stdlib.h>
#include "bpf_tcp_helpers.h"

char _license[] SEC("license") = "GPL";
#define __ALIGN(x, a)		__ALIGN_MASK(x, (typeof(x))(a) - 1)
#define __ALIGN_MASK(x, mask)	(((x) + (mask)) & ~(mask))
#define L1_CACHE_ALIGN(x) __ALIGN(x, 64)
#define TCP_INFINITE_SSTHRESH	0x7fffffff

/* Two methods of hybrid slow start */
#define HYSTART_ACK_TRAIN	0x1
#define HYSTART_DELAY		0x2
/* Number of delay samples for detecting the increase of delay */
#define HYSTART_MIN_SAMPLES	8
#define HYSTART_DELAY_MIN	(4000U)	/* 4ms */
#define HYSTART_DELAY_MAX	(16000U)	/* 16 ms */
#define HYSTART_DELAY_THRESH(x)	clamp(x, HYSTART_DELAY_MIN, HYSTART_DELAY_MAX)
#define GSO_MAX_SIZE		65536
#define MAX_TCP_HEADER	L1_CACHE_ALIGN(128 + MAX_HEADER)
#define MAX_HEADER 128
extern unsigned long CONFIG_HZ __kconfig;
#define HZ CONFIG_HZ

__u32 flowkey = 0;
__u32 alf=1;
enum control_mod {
	URGENT = 1,
	NORMAL = 2,
};
enum playerType {
	ACTION_4k = 1,
	ACTION_COMPUTER = 2,
	ACTION_PHONE = 3,
	FOOD_4k = 4,
	FOOD_COMPUTER = 5,
	FOOD_PHONE = 6,
	CARTOON_4k =7,
	CARTOON_COMPUTER =8,
	CARTOON_PHONE =9,
	SPORT_4k =10,
	SPORT_COMPUTER =11,
	SPORT_PHONE =12,
};
__u32 control_state = 0;

struct bbr_params {
	__u32 flow_key; 
	__u32 app_limited;
	__u32 advice_cwnd;
	bool is_used_advice_cwnd;
	__u64 pacing_rate;
	__u16 loss_cnt;
	__u32 sample_lost;
	__u32 prior_sample_lost;
	__u32 prior_sample_delivered;
	__u32 delivered;
	__u16 loss_in_round:8,
		  loss_events_in_round:8;
	__u32 loss_round_delivered;
	bool is_app_limited;
	bool loss_round_start;
};

struct u_params{
	__u64 a;
};

struct flow_param{
	long target_rate;
	int player_type; 
	int mode; 
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 10240);
	__type(key, __u16);
	__type(value, struct bbr_params);
} paramMap SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 20);
	__type(key, __u16);
	__type(value, struct u_params);
} uMap SEC(".maps");
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 20);
	__type(key, __u16);
	__type(value, struct flow_param);
} flowRateMap SEC(".maps");

#define BW_SCALE 24
#define BW_UNIT (1 << BW_SCALE)

#define Param_UNIT 1000000

#define BBR_SCALE 8	/* scaling factor for fractions in BBR (e.g. gains) */
#define BBR_UNIT (1 << BBR_SCALE)

static __always_inline __u32 tcp_min_rtt(const struct tcp_sock *tp)
{
	return my_minmax_get(&tp->rtt_min);
}
static __always_inline __u64 div64_u64(__u64 dividend, __u64 divisor)
{
	return dividend / divisor;
}
struct bbr_context {
	__u32 sample_bw;
	__u32 target_cwnd;
	__u32 log:1;
};

#define div64_ul div64_u64
#define NSEC_PER_USEC	1000L
#define TCP_INIT_CWND	10

/* BBR has the following modes for deciding how fast to send: */
enum bbr_mode {
	BBR_STARTUP,	/* ramp up sending rate rapidly to fill pipe */
	BBR_DRAIN,	/* drain any queue created during startup */
	BBR_PROBE_BW,	/* discover, share bw: pace around estimated bw */
	BBR_PROBE_RTT,	/* cut inflight to min to probe min_rtt */
};


struct bbr {
	__u32	min_rtt_us;	        /* min RTT in min_rtt_win_sec window */
	__u32	min_rtt_stamp;	        /* timestamp of min_rtt_us */
	__u32	probe_rtt_done_stamp;   /* end time for BBR_PROBE_RTT mode */
	struct my_minmax bw;	/* Max recent delivery rate in pkts/uS << 24 */
	__u32	rtt_cnt;	    /* count of packet-timed rounds elapsed */
	__u32     next_rtt_delivered; /* scb->tx.delivered at end of round */
	__u64	cycle_mstamp;	     /* time of this cycle phase start */
	__u32     mode:3,		     /* current bbr_mode in state machine */
		prev_ca_state:3,     /* CA state on previous ACK */
		packet_conservation:1,  /* use packet conservation? */
		round_start:1,	     /* start of packet-timed tx->ack round? */
		idle_restart:1,	     /* restarting after idle? */
		probe_rtt_round_done:1,  /* a BBR_PROBE_RTT round at 4 pkts? */
		unused:13,
		lt_is_sampling:1,    /* taking long-term ("LT") samples now? */
		lt_rtt_cnt:7,	     /* round trips in long-term interval */
		lt_use_bw:1;	     /* use lt_bw as our bw estimate? */
	__u32	lt_bw;		     /* LT est delivery rate in pkts/uS << 24 */
	__u32	lt_last_delivered;   /* LT intvl start: tp->delivered */
	__u32	lt_last_stamp;	     /* LT intvl start: tp->delivered_mstamp */
	__u32	lt_last_lost;	     /* LT intvl start: tp->lost */
	__u32	pacing_gain:10,	/* current gain for setting pacing rate */
		cwnd_gain:10,	/* current gain for setting cwnd */
		full_bw_reached:1,   /* reached full bw in Startup? */
		full_bw_cnt:2,	/* number of rounds without large bw gains */
		cycle_idx:3,	/* current index in pacing_gain cycle array */
		has_seen_rtt:1, /* have we seen an RTT sample yet? */
		unused_b:5;
	__u32	prior_cwnd;	/* prior cwnd upon entering loss recovery */
	__u32	full_bw;	/* recent bw, to estimate if pipe is full */
	/* For tracking ACK aggregation: */
	__u64	ack_epoch_mstamp;	/* start of ACK sampling epoch */
	__u16	extra_acked[2];		/* max excess data ACKed in epoch */
	__u32	ack_epoch_acked:20,	/* packets (S)ACKed in sampling epoch */
		extra_acked_win_rtts:5,	/* age of extra_acked, in round trips */
		extra_acked_win_idx:1,	/* current index in extra_acked array */
		unused_c:6;

};

#define USEC_PER_MSEC	1000UL
#define USEC_PER_SEC	1000000UL
#define CYCLE_LEN	8	/* number of phases in a pacing gain cycle */



/* Window length of bw filter (in rounds): */
static const int bbr_bw_rtts = CYCLE_LEN + 2;
/* Window length of min_rtt filter (in sec): */
static const __u32 bbr_min_rtt_win_sec = 10;
/* Minimum time (in ms) spent at bbr_cwnd_min_target in BBR_PROBE_RTT mode: */
static const __u32 bbr_probe_rtt_mode_ms = 200;
/* Skip TSO below the following bandwidth (bits/sec): */
static const int bbr_min_tso_rate = 1200000;

static __u32 bbr_full_loss_cnt = 3;
static __u32 bbr_beta = BBR_UNIT * 30 / 100;
static __u32 bbr_loss_thresh = BBR_UNIT * 2 / 100;
/* Pace at ~1% below estimated bw, on average, to reduce queue at bottleneck.
 * In order to help drive the network toward lower queues and low latency while
 * maintaining high utilization, the average pacing rate aims to be slightly
 * lower than the estimated bandwidth. This is an important aspect of the
 * design.
 */
static const int bbr_pacing_margin_percent = 1;
static __u32 bbr_probe_rtt_win_urgent_sec = 5;
static __u32 bbr_probe_rtt_cwnd_gain = BBR_UNIT * 1 / 2;
/* We use a high_gain value of 2/ln(2) because it's the smallest pacing gain
 * that will allow a smoothly increasing pacing rate that will double each RTT
 * and send the same number of packets per RTT that an un-paced, slow-starting
 * Reno or CUBIC flow would:
 */
static const int bbr_high_gain  = BBR_UNIT * 2885 / 1000 + 1;
/* The pacing gain of 1/high_gain in BBR_DRAIN is calculated to typically drain
 * the queue created in BBR_STARTUP in a single round:
 */
static const int bbr_drain_gain = BBR_UNIT * 1000 / 2885;
/* The gain for deriving steady-state cwnd tolerates delayed/stretched ACKs: */
static const int bbr_cwnd_gain  = BBR_UNIT * 2;
/* The pacing_gain values for the PROBE_BW gain cycle, to discover/share bw: */
static const int bbr_pacing_gain[] = {
	BBR_UNIT * 5 / 4,	/* probe for more available bw */
	BBR_UNIT * 3 / 4,	/* drain queue and/or yield bw to other flows */
	BBR_UNIT, BBR_UNIT, BBR_UNIT,	/* cruise at 1.0*bw to utilize pipe, */
	BBR_UNIT, BBR_UNIT, BBR_UNIT	/* without creating excess queue... */
};
/* Randomize the starting gain cycling phase over N phases: */
static const __u32 bbr_cycle_rand = 7;

/* Try to keep at least this many packets in flight, if things go smoothly. For
 * smooth functioning, a sliding window protocol ACKing every other packet
 * needs at least 4 packets in flight:
 */
static const __u32 bbr_cwnd_min_target = 4;

/* To estimate if BBR_STARTUP mode (i.e. high_gain) has filled pipe... */
/* If bw has increased significantly (1.25x), there may be more bw available: */
static const __u32 bbr_full_bw_thresh = BBR_UNIT * 5 / 4;
/* But after 3 rounds w/o significant bw growth, estimate pipe is full: */
static const __u32 bbr_full_bw_cnt = 3;

/* "long-term" ("LT") bandwidth estimator parameters... */
/* The minimum number of rounds in an LT bw sampling interval: */
static const __u32 bbr_lt_intvl_min_rtts = 4;
/* If lost/delivered ratio > 20%, interval is "lossy" and we may be policed: */
static const __u32 bbr_lt_loss_thresh = 50;
/* If 2 intervals have a bw ratio <= 1/8, their bw is "consistent": */
static const __u32 bbr_lt_bw_ratio = BBR_UNIT / 8;
/* If 2 intervals have a bw diff <= 4 Kbit/sec their bw is "consistent": */
static const __u32 bbr_lt_bw_diff = 4000 / 8;
/* If we estimate we're policed, use lt_bw for this many round trips: */
static const __u32 bbr_lt_bw_max_rtts = 48;

/* Gain factor for adding extra_acked to target cwnd: */
static const int bbr_extra_acked_gain = BBR_UNIT;
/* Window length of extra_acked window. */
static const __u32 bbr_extra_acked_win_rtts = 5;
/* Max allowed val for ack_epoch_acked, after which sampling epoch is reset */
static const __u32 bbr_ack_epoch_acked_reset_thresh = 1U << 20;
/* Time period for clamping cwnd increment due to ack aggregation */
static const __u32 bbr_extra_acked_max_us = 100 * 1000;
static __always_inline void bbr_check_probe_rtt_done(struct sock *sk);
static __always_inline __u64 bbr_rate_bytes_per_sec(struct sock *sk, __u64 rate, int gain);
static void bbr2_check_loss_too_high_in_startup(struct sock *sk,
					       const struct rate_sample *rs);

static __always_inline bool bbr_full_bw_reached(const struct sock *sk)
{
	const struct bbr *bbr = inet_csk_ca(sk);

	return bbr->full_bw_reached;
}

/* Return the windowed max recent bandwidth sample, in pkts/uS << BW_SCALE. */
static __always_inline __u32 bbr_max_bw(const struct sock *sk)
{
	struct bbr *bbr = inet_csk_ca(sk);
	return my_minmax_get(&bbr->bw);
}

/* Return the estimated bandwidth of the path, in pkts/uS << BW_SCALE. */
static __always_inline __u32 bbr_bw(const struct sock *sk)
{
	struct bbr *bbr = inet_csk_ca(sk);
	return bbr->lt_use_bw ? bbr->lt_bw : bbr_max_bw(sk);
}

/* Return maximum extra acked in past k-2k round trips,
 * where k = bbr_extra_acked_win_rtts.
 */
static __always_inline __u16 bbr_extra_acked(const struct sock *sk)
{
	struct bbr *bbr = inet_csk_ca(sk);
	return max(bbr->extra_acked[0], bbr->extra_acked[1]);
}
static struct flow_param* getFlowParam(struct bbr_params *bbr_param){
	
	struct flow_param *flow = bpf_map_lookup_elem(&flowRateMap, &(bbr_param->flow_key));
	if(flow){
		
		return flow;
	}else{
		bpf_printk( "flowRateMap value do not\n");
		struct flow_param tempFlow = {0,0,1};
		bpf_map_update_elem(&flowRateMap, &(bbr_param->flow_key), &tempFlow, BPF_ANY);
		flow = &tempFlow;
		return flow;
	}
}
static struct u_params* getuParam(int player_type){
	
	struct u_params *uParam = bpf_map_lookup_elem(&uMap, &player_type);
	if(uParam){
	
		return uParam;
	}else{
		if(player_type>12){
			return NULL;
		}
		bpf_printk( "getuParam no value player_type:%d BBR_UNIT:%u\n",player_type,BBR_UNIT);
		struct u_params Action_4k = {Param_UNIT*2.4455};
		struct u_params Action_computer = {Param_UNIT*1.6611};
		struct u_params Action_phone = {Param_UNIT*1.6927};
		struct u_params Food_4k = {Param_UNIT*2.4322};
		struct u_params Food_computer = {Param_UNIT*1.7435};
		struct u_params Food_phone = {Param_UNIT*2.0071};
		struct u_params Cartoon_4k = {Param_UNIT*1.8509};
		struct u_params Cartoon_computer = {Param_UNIT*1.8749};
		struct u_params Cartoon_phone = {Param_UNIT*1.7551};
		struct u_params Sport_4k = {Param_UNIT*2.0876};
		struct u_params Sport_computer = {Param_UNIT*1.6618};
		struct u_params Sport_phone = {Param_UNIT*1.6542};

		__u16 key1 = ACTION_4k;
		__u16 key2 = ACTION_COMPUTER;
		__u16 key3 = ACTION_PHONE;
		__u16 key4 = FOOD_4k;
		__u16 key5 = FOOD_COMPUTER;
		__u16 key6 = FOOD_PHONE;
		__u16 key7 = CARTOON_4k;
		__u16 key8 = CARTOON_COMPUTER;
		__u16 key9 = CARTOON_PHONE;
		__u16 key10 = SPORT_4k;
		__u16 key11 = SPORT_COMPUTER;
		__u16 key12 = SPORT_PHONE;
		bpf_map_update_elem(&uMap, &key1, &Action_4k, BPF_ANY);
		bpf_map_update_elem(&uMap, &key2, &Action_computer, BPF_ANY);
		bpf_map_update_elem(&uMap, &key3, &Action_phone, BPF_ANY);
		bpf_map_update_elem(&uMap, &key4, &Food_4k, BPF_ANY);
		bpf_map_update_elem(&uMap, &key5, &Food_computer, BPF_ANY);
		bpf_map_update_elem(&uMap, &key6, &Food_phone, BPF_ANY);
		bpf_map_update_elem(&uMap, &key7, &Cartoon_4k, BPF_ANY);
		bpf_map_update_elem(&uMap, &key8, &Cartoon_computer, BPF_ANY);
		bpf_map_update_elem(&uMap, &key9, &Cartoon_phone, BPF_ANY);
		bpf_map_update_elem(&uMap, &key10, &Sport_4k, BPF_ANY);
		bpf_map_update_elem(&uMap, &key11, &Sport_computer, BPF_ANY);
		bpf_map_update_elem(&uMap, &key12, &Sport_phone, BPF_ANY);
		struct u_params *temp_uParam = bpf_map_lookup_elem(&uMap, &player_type);
		uParam=temp_uParam;
		return uParam;
	}
}

static __always_inline __u64 bbr_rate_bytes_per_sec_1450mss(struct sock *sk, __u64 rate, int gain)
{
	rate *= 1450;
	rate *= gain;
	rate >>= BBR_SCALE;
	rate *= USEC_PER_SEC / 100 * (100 - bbr_pacing_margin_percent);
	return rate >> BW_SCALE;
}


static __always_inline int rateGain(struct sock * sk, struct bbr_params *bbr_param,int gain){
	__u16 sport = sk->__sk_common.skc_num;	

	__u64 rate = bbr_rate_bytes_per_sec_1450mss(sk, (__u64)bbr_bw(sk), BBR_UNIT);
	//bpf_printk( ">>>>>>>>>>rate:%u bw:%u \n",rate,bbr_bw(sk));

	struct flow_param *flow = getFlowParam(bbr_param);

	struct u_params *uParam = getuParam(flow->player_type);
	if(!uParam || rate == 0){
		return gain;
	}
	//bpf_printk( "get uParam a:%u\n",uParam->a);

	
	__u16 qoe_rate = uParam->a/rate;
	if(qoe_rate<9){
		qoe_rate=9;
	}else{
		if(qoe_rate>11){
			qoe_rate=11;
		}
	} 
	__u64 new_gain = gain*flow->target_rate*qoe_rate*alf/rate;
	new_gain = new_gain/10;
	bpf_printk( "first new gain:%d  gain:%d qoe_rate:%u\n",new_gain,gain,qoe_rate);

	if(new_gain ==0){
		return gain;
	}
	if(new_gain<0.75*gain){
		new_gain = 0.75*gain;
	}
	if(new_gain >1.25*gain){
		new_gain = 1.25*gain;
	}
	if(flow->mode == URGENT){
			new_gain = max(gain,new_gain);	
	}

	if(flow->mode ==NORMAL && bbr_param->loss_in_round>0){
		new_gain = min(new_gain,gain);
	}
	bpf_printk( "final new dport:%u gain:%d  gain:%d \n",sk->__sk_common.skc_dport,(int)new_gain,gain);

	return new_gain;
}

static struct bbr_params* getBBRParam(struct sock *sk){
	struct bbr *bbr = inet_csk_ca(sk);
	__u16 sport = sk->__sk_common.skc_num;

	__u16 dport = sk->__sk_common.skc_dport;
	//struct bbr_params *param = NULL;
	struct bbr_params *param = bpf_map_lookup_elem(&paramMap, &dport);

	if (!param){
			struct bbr_params newParam = {flowkey,0,0,true,0,0,0,0,0,0,0,0,false,false};
			bpf_map_update_elem(&paramMap, &dport, &newParam, BPF_ANY);
			param = &newParam;
			bpf_printk( "dont getBBRParam dport: %u, param->flowkey: %u, sport:%u\n", dport,param->flow_key,sport);

		}else{
			
			//param->mod = mod;
			//bpf_printk( "enter getBBRParam dport: %u, param_mod: %u, mod:%u\n", dport,param->mod,mod);
			if(param->flow_key == 0){
				param->flow_key = flowkey;
			}
			return param;
		}
	
	return param;
}

/* Return rate in bytes per second, optionally with a gain.
 * The order here is chosen carefully to avoid overflow of u64. This should
 * work for input rates of up to 2.9Tbit/sec and gain of 2.89x.
 */
static __always_inline __u64 bbr_rate_bytes_per_sec(struct sock *sk, __u64 rate, int gain)
{
	unsigned int mss = tcp_sk(sk)->mss_cache; 
	rate *= mss;
	rate *= gain;
	rate >>= BBR_SCALE;
	rate *= USEC_PER_SEC / 100 * (100 - bbr_pacing_margin_percent);
	return rate >> BW_SCALE;
}
/* Convert a BBR bw and gain factor to a pacing rate in bytes per second. */
static __always_inline unsigned long bbr_bw_to_pacing_rate(struct sock *sk, __u64 bw, int gain)
{
	__u64 rate = bw;
	rate = bbr_rate_bytes_per_sec(sk, rate, gain);
	rate = min((__u64)rate, (__u64)sk->sk_max_pacing_rate);
	return rate;
}
/* Initialize pacing rate to: high_gain * init_cwnd / RTT. */
static __always_inline void bbr_init_pacing_rate_from_rtt(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct bbr *bbr = inet_csk_ca(sk);
	__u64 bw;
	__u32 rtt_us;
	struct bbr_params* param = getBBRParam(sk);


	if (tp->srtt_us) {		/* any RTT sample yet? */
		rtt_us = max(tp->srtt_us >> 3, 1U);
		bbr->has_seen_rtt = 1;
	} else {			 /* no RTT sample yet */
		rtt_us = USEC_PER_MSEC;	 /* use nominal default RTT */
	}
	bw = (__u64)tp->snd_cwnd * BW_UNIT;
	bw = div64_u64(bw, (__u64)rtt_us);
	param->pacing_rate = bbr_bw_to_pacing_rate(sk, bw, bbr_high_gain);
}

/* Pace using current bw estimate and a gain factor. */
static __always_inline void bbr_set_pacing_rate(struct sock *sk, __u32 bw, int gain)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct bbr_params* param = getBBRParam(sk);

	struct bbr *bbr = inet_csk_ca(sk);
	unsigned long rate = bbr_bw_to_pacing_rate(sk, (__u64)bw, gain);
	if (unlikely(!bbr->has_seen_rtt && tp->srtt_us))
		bbr_init_pacing_rate_from_rtt(sk);
	if (bbr_full_bw_reached(sk) || rate > param->pacing_rate)
		param->pacing_rate = rate;
}

/* override sysctl_tcp_min_tso_segs */
static __always_inline __u32 bbr_min_tso_segs(struct sock *sk)
{
	struct bbr_params* param = getBBRParam(sk);

	return param->pacing_rate < (bbr_min_tso_rate >> 3) ? 1 : 2;
}


static __always_inline __u32 bbr_tso_segs_goal(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);
	__u32 segs, bytes;
	struct bbr *bbr = inet_csk_ca(sk);
	/* Sort of tcp_tso_autosize() but ignoring
	 * driver provided sk_gso_max_size.
	 */
	struct bbr_params* param = getBBRParam(sk);

	bytes = min((unsigned long)( param->pacing_rate >> sk->sk_pacing_shift),
		      (unsigned long)(GSO_MAX_SIZE - 1 - MAX_TCP_HEADER));
	segs = max((__u32)(bytes / tp->mss_cache), (__u32)(bbr_min_tso_segs(sk)));

	return min(segs, 0x7FU);
}
/* Save "last known good" cwnd so we can restore it after losses or PROBE_RTT */
static __always_inline void bbr_save_cwnd(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct bbr *bbr = inet_csk_ca(sk);

	if (bbr->prev_ca_state < TCP_CA_Recovery && bbr->mode != BBR_PROBE_RTT)
		bbr->prior_cwnd = tp->snd_cwnd;  /* this cwnd is good enough */
	else  /* loss recovery or BBR_PROBE_RTT have temporarily cut cwnd */
		bbr->prior_cwnd = max(bbr->prior_cwnd, tp->snd_cwnd);
}

void BPF_STRUCT_OPS(bbr_cwnd_event, struct sock *sk, enum tcp_ca_event event)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct bbr *bbr = inet_csk_ca(sk);
	struct bbr_params* param = getBBRParam(sk);

	if (event == CA_EVENT_TX_START && param->app_limited) {
		bbr->idle_restart = 1;
		bbr->ack_epoch_mstamp = tp->tcp_mstamp;
		bbr->ack_epoch_acked = 0;
		/* Avoid pointless buffer overflows: pace at est. bw if we don't
		 * need more speed (we're restarting from idle and app-limited).
		 */
		if (bbr->mode == BBR_PROBE_BW)
			bbr_set_pacing_rate(sk, bbr_bw(sk), BBR_UNIT);
		 else if (bbr->mode == BBR_PROBE_RTT)
		 	bbr_check_probe_rtt_done(sk);
	}
}
/* Calculate bdp based on min RTT and the estimated bottleneck bandwidth:
 * bdp = ceil(bw * min_rtt * gain)
 * The key factor, gain, controls the amount of queue. While a small gain
 * builds a smaller queue, it becomes more vulnerable to noise in RTT
 * measurements (e.g., delayed ACKs or other ACK compression effects). This
 * noise may cause BBR to under-estimate the rate.
 */
static __always_inline __u32 bbr_bdp(struct sock *sk, __u32 bw, int gain)
{
	struct bbr *bbr = inet_csk_ca(sk);
	__u32 bdp=0;
	__u64 w=0;

	/* If we've never had a valid RTT sample, cap cwnd at the initial
	 * default. This should only happen when the connection is not using TCP
	 * timestamps and has retransmitted all of the SYN/SYNACK/data packets
	 * ACKed so far. In this case, an RTO can cut cwnd to 1, in which
	 * case we need to slow-start up toward something safe: TCP_INIT_CWND.
	 */
	if (unlikely(bbr->min_rtt_us == ~0U))	 /* no valid RTT samples yet? */
		return TCP_INIT_CWND;  /* be safe: cap at default initial cwnd*/

	w = (__u64)bw * bbr->min_rtt_us;

	/* Apply a gain to the given value, remove the BW_SCALE shift, and
	 * round the value up to avoid a negative feedback loop.
	 */
	// __u64 temp_bdp = (__u64)(w >>BBR_SCALE)* gain;
	// __u64 t_bdp = (w * gain)>>BBR_SCALE;
	// __u64 div = 1*BW_UNIT;
	// __u64 next_bdp = t_bdp>>BW_SCALE;
	// bpf_printk( "bbr_bdp temp_bdp: %lld, t_bdp: %lld next_bdp5: %lld\n",temp_bdp, t_bdp,next_bdp );

	bdp = (((w * gain) >> BBR_SCALE) + BW_UNIT - 1) / BW_UNIT;
	//bpf_printk( "bbr_bdp bdp: %lld, w: %lld,gain:%lld\n",bdp,w,gain);

	return bdp;
}
/* To achieve full performance in high-speed paths, we budget enough cwnd to
 * fit full-sized skbs in-flight on both end hosts to fully utilize the path:
 *   - one skb in sending host Qdisc,
 *   - one skb in sending host TSO/GSO engine
 *   - one skb being received by receiver host LRO/GRO/delayed-ACK engine
 * Don't worry, at low rates (bbr_min_tso_rate) this won't bloat cwnd because
 * in such cases tso_segs_goal is 1. The minimum cwnd is 4 packets,
 * which allows 2 outstanding 2-packet sequences, to try to keep pipe
 * full even with ACK-every-other-packet delayed ACKs.
 */
static __always_inline __u32 bbr_quantization_budget(struct sock *sk, __u32 cwnd)
{
	struct bbr *bbr = inet_csk_ca(sk);

	/* Allow enough full-sized skbs in flight to utilize end systems. */
	cwnd += 3 * bbr_tso_segs_goal(sk);

	/* Reduce delayed ACKs by rounding up cwnd to the next even number. */
	cwnd = (cwnd + 1) & ~1U;

	/* Ensure gain cycling gets inflight above BDP even for small BDPs. */
	if (bbr->mode == BBR_PROBE_BW && bbr->cycle_idx == 0)
		cwnd += 2;

	return cwnd;
}
/* Find inflight based on min RTT and the estimated bottleneck bandwidth. */
static __always_inline __u32 bbr_inflight(struct sock *sk, __u32 bw, int gain)
{
	__u32 inflight;

	inflight = bbr_bdp(sk, bw, gain);
	inflight = bbr_quantization_budget(sk, inflight);

	return inflight;
}


/* With pacing at lower layers, there's often less data "in the network" than
 * "in flight". With TSQ and departure time pacing at lower layers (e.g. fq),
 * we often have several skbs queued in the pacing layer with a pre-scheduled
 * earliest departure time (EDT). BBR adapts its pacing rate based on the
 * inflight level that it estimates has already been "baked in" by previous
 * departure time decisions. We calculate a rough estimate of the number of our
 * packets that might be in the network at the earliest departure time for the
 * next skb scheduled:
 *   in_network_at_edt = inflight_at_edt - (EDT - now) * bw
 * If we're increasing inflight, then we want to know if the transmit of the
 * EDT skb will push inflight above the target, so inflight_at_edt includes
 * bbr_tso_segs_goal() from the skb departing at EDT. If decreasing inflight,
 * then estimate if inflight will sink too low just before the EDT transmit.
 */
static __always_inline __u32 bbr_packets_in_net_at_edt(struct sock *sk, __u32 inflight_now)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct bbr *bbr = inet_csk_ca(sk);
	__u64 now_ns, edt_ns, interval_us;
	__u32 interval_delivered, inflight_at_edt;

	now_ns = tp->tcp_clock_cache;
	edt_ns = max(tp->tcp_wstamp_ns, now_ns);
	interval_us = div64_u64(edt_ns - now_ns, NSEC_PER_USEC);
	interval_delivered = (__u64)bbr_bw(sk) * interval_us >> BW_SCALE;
	inflight_at_edt = inflight_now;
	if (bbr->pacing_gain > BBR_UNIT)              /* increasing inflight */
		inflight_at_edt += bbr_tso_segs_goal(sk);  /* include EDT skb */
	if (interval_delivered >= inflight_at_edt)
		return 0;
	return inflight_at_edt - interval_delivered;
}
/* Find the cwnd increment based on estimate of ack aggregation */
static __always_inline __u32 bbr_ack_aggregation_cwnd(struct sock *sk)
{
	__u32 max_aggr_cwnd, aggr_cwnd = 0;

	if (bbr_extra_acked_gain && bbr_full_bw_reached(sk)) {
		max_aggr_cwnd = ((__u64)bbr_bw(sk) * bbr_extra_acked_max_us)
				/ BW_UNIT;
		aggr_cwnd = (bbr_extra_acked_gain * bbr_extra_acked(sk))
			     >> BBR_SCALE;
		aggr_cwnd = min(aggr_cwnd, max_aggr_cwnd);
	}

	return aggr_cwnd;
}
/* An optimization in BBR to reduce losses: On the first round of recovery, we
 * follow the packet conservation principle: send P packets per P packets acked.
 * After that, we slow-start and send at most 2*P packets per P packets acked.
 * After recovery finishes, or upon undo, we restore the cwnd we had when
 * recovery started (capped by the target cwnd based on estimated BDP).
 *
 * TODO(ycheng/ncardwell): implement a rate-based approach.
 */
static __always_inline bool bbr_set_cwnd_to_recover_or_restore(
	struct sock *sk, const struct rate_sample *rs, __u32 acked, __u32 *new_cwnd)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct bbr *bbr = inet_csk_ca(sk);
	__u8 prev_state = bbr->prev_ca_state, state = inet_csk(sk)->icsk_ca_state;
	__u32 cwnd = tp->snd_cwnd;

	/* An ACK for P pkts should release at most 2*P packets. We do this
	 * in two steps. First, here we deduct the number of lost packets.
	 * Then, in bbr_set_cwnd() we slow start up toward the target cwnd.
	 */
	if (rs->losses > 0)
		cwnd = max((int)cwnd - rs->losses, (int)1);

	if (state == TCP_CA_Recovery && prev_state != TCP_CA_Recovery) {
		/* Starting 1st round of Recovery, so do packet conservation. */
		bbr->packet_conservation = 1;
		bbr->next_rtt_delivered = tp->delivered;  /* start round now */
		/* Cut unused cwnd from app behavior, TSQ, or TSO deferral: */
		cwnd = tcp_packets_in_flight(tp) + acked;
	} else if (prev_state >= TCP_CA_Recovery && state < TCP_CA_Recovery) {
		/* Exiting loss recovery; restore cwnd saved before recovery. */
		cwnd = max(cwnd, bbr->prior_cwnd);
		bbr->packet_conservation = 0;
	}
	bbr->prev_ca_state = state;

	if (bbr->packet_conservation) {
		*new_cwnd = max(cwnd, tcp_packets_in_flight(tp) + acked);
		return true;	/* yes, using packet conservation */
	}
	*new_cwnd = cwnd;
	return false;
}

static __u32 bbr_probe_rtt_cwnd(struct sock *sk)
{
	struct bbr *bbr = inet_csk_ca(sk);
	struct bbr_params* param = getBBRParam(sk);
	struct flow_param *flow = getFlowParam(param);
	if (bbr_probe_rtt_cwnd_gain == 0 || flow->mode ==NORMAL)
		return bbr_cwnd_min_target;
	return max((__u32)bbr_cwnd_min_target,
		     bbr_bdp(sk, bbr_bw(sk), bbr_probe_rtt_cwnd_gain));
}

/* Slow-start up toward target cwnd (if bw estimate is growing, or packet loss
 * has drawn us down below target), or snap down to target if we're above it.
 */
static __always_inline void bbr_set_cwnd(struct sock *sk, const struct rate_sample *rs,
			 __u32 acked, __u32 bw, int gain)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct bbr *bbr = inet_csk_ca(sk);
	__u32 cwnd = tp->snd_cwnd, target_cwnd = 0;
	struct bbr_params* param = getBBRParam(sk);
	__u16 sport = sk->__sk_common.skc_num;	

	if (!acked)
		goto done;  /* no packet fully ACKed; just apply caps */

	if (bbr_set_cwnd_to_recover_or_restore(sk, rs, acked, &cwnd))
		goto done;

	target_cwnd = bbr_bdp(sk, bw, gain);
	if (sport == 80){
	bpf_printk( "target_cwnd: %u, gain: %d\n",target_cwnd,gain);
	}
	/* Increment the cwnd to account for excess ACKed data that seems
	 * due to aggregation (of data and/or ACKs) visible in the ACK stream.
	 */
	target_cwnd += bbr_ack_aggregation_cwnd(sk);
	target_cwnd = bbr_quantization_budget(sk, target_cwnd);

	/* If we're below target cwnd, slow start cwnd toward target cwnd. */
	if (bbr_full_bw_reached(sk))  /* only cut cwnd if we filled the pipe */
		cwnd = min(cwnd + acked, target_cwnd);
	else if (cwnd < target_cwnd || tp->delivered < TCP_INIT_CWND)
		cwnd = cwnd + acked;
	cwnd = max(cwnd, bbr_cwnd_min_target);

done:
	tp->snd_cwnd = min(cwnd, tp->snd_cwnd_clamp);	/* apply global cap */
	if (bbr->mode == BBR_PROBE_RTT){  /* drain queue, refresh min_rtt */
		__u32 probe_cwnd = 	 bbr_probe_rtt_cwnd(sk);
		tp->snd_cwnd = min(tp->snd_cwnd,probe_cwnd);	
		if (sport == 80){
		bpf_printk( "enter set_cwnd flow_key: %u, probe_cwnd: %u\n"
		,param->flow_key, probe_cwnd);
		bpf_printk( "enter set_cwnd probe_cwnd sport: %u, dport: %u\n"
		,sport, sk->__sk_common.skc_dport);
	}
	}
 	if(param->is_used_advice_cwnd==false){
		 tp->snd_cwnd = min(tp->snd_cwnd, param->advice_cwnd);
		 param->is_used_advice_cwnd = true;
	 }
	 unsigned long long curtime;
	curtime = bpf_ktime_get_ns();
	if (sport == 80){
		bpf_printk( "enter set_cwnd flow_key: %u, cwnd: %u ; mode: %u \n"
		,param->flow_key, tp->snd_cwnd, bbr->mode);
		bpf_printk( "enter set_cwnd sport: %u, dport: %u\n"
		,sport, sk->__sk_common.skc_dport);
	}

}
static __always_inline __u32 tcp_stamp_us_delta(__u64 t1, __u64 t0)
{
	return max((int)t1 - t0, (int)0);
}
/* End cycle phase if it's time and/or we hit the phase's in-flight target. */
static __always_inline bool bbr_is_next_cycle_phase(struct sock *sk,
				    const struct rate_sample *rs)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct bbr *bbr = inet_csk_ca(sk);
	bool is_full_length =
		tcp_stamp_us_delta(tp->delivered_mstamp, bbr->cycle_mstamp) >
		bbr->min_rtt_us;
	__u32 inflight, bw;

	/* The pacing_gain of 1.0 paces at the estimated bw to try to fully
	 * use the pipe without increasing the queue.
	 */
	if (bbr->pacing_gain == BBR_UNIT)
		return is_full_length;		/* just use wall clock time */

	inflight = bbr_packets_in_net_at_edt(sk, rs->prior_in_flight);
	bw = bbr_max_bw(sk);

	/* A pacing_gain > 1.0 probes for bw by trying to raise inflight to at
	 * least pacing_gain*BDP; this may take more than min_rtt if min_rtt is
	 * small (e.g. on a LAN). We do not persist if packets are lost, since
	 * a path with small buffers may not hold that much.
	 */
	if (bbr->pacing_gain > BBR_UNIT)
		return is_full_length &&
			(rs->losses ||  /* perhaps pacing_gain*BDP won't fit */
			 inflight >= bbr_inflight(sk, bw, bbr->pacing_gain));

	/* A pacing_gain < 1.0 tries to drain extra queue we added if bw
	 * probing didn't find more bw. If inflight falls to match BDP then we
	 * estimate queue is drained; persisting would underutilize the pipe.
	 */
	return is_full_length ||
		inflight <= bbr_inflight(sk, bw, BBR_UNIT);
}
static __always_inline void bbr_advance_cycle_phase(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct bbr *bbr = inet_csk_ca(sk);

	bbr->cycle_idx = (bbr->cycle_idx + 1) & (CYCLE_LEN - 1);
	bbr->cycle_mstamp = tp->delivered_mstamp;
}

/* Gain cycling: cycle pacing gain to converge to fair share of available bw. */
static __always_inline void bbr_update_cycle_phase(struct sock *sk,
				   const struct rate_sample *rs)
{
	struct bbr *bbr = inet_csk_ca(sk);

	if (bbr->mode == BBR_PROBE_BW && bbr_is_next_cycle_phase(sk, rs))
		bbr_advance_cycle_phase(sk);
}

static __always_inline void bbr_reset_startup_mode(struct sock *sk)
{
	struct bbr *bbr = inet_csk_ca(sk);

	bbr->mode = BBR_STARTUP;
}
static __always_inline __u32 prandom_u32_max(__u32 ep_ro)
{
	return (__u32)((__u64) bpf_get_prandom_u32() % ep_ro);
}

static  __always_inline void bbr_reset_probe_bw_mode(struct sock *sk)
{
	struct bbr *bbr = inet_csk_ca(sk);

	bbr->mode = BBR_PROBE_BW;
	bbr->cycle_idx = CYCLE_LEN - 1 - prandom_u32_max(bbr_cycle_rand);
	bbr_advance_cycle_phase(sk);	/* flip to next phase of gain cycle */
}

static  __always_inline void bbr_reset_mode(struct sock *sk)
{
	if (!bbr_full_bw_reached(sk))
		bbr_reset_startup_mode(sk);
	else
		bbr_reset_probe_bw_mode(sk);
}
/* Start a new long-term sampling interval. */
static  __always_inline void bbr_reset_lt_bw_sampling_interval(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct bbr *bbr = inet_csk_ca(sk);

	bbr->lt_last_stamp = div64_u64(tp->delivered_mstamp, USEC_PER_MSEC);
	bbr->lt_last_delivered = tp->delivered;
	bbr->lt_last_lost = tp->lost;
	bbr->lt_rtt_cnt = 0;
}

/* Completely reset long-term bandwidth sampling. */
static  __always_inline void bbr_reset_lt_bw_sampling(struct sock *sk)
{
	struct bbr *bbr = inet_csk_ca(sk);

	bbr->lt_bw = 0;
	bbr->lt_use_bw = 0;
	bbr->lt_is_sampling = false;
	bbr_reset_lt_bw_sampling_interval(sk);
}

/* Long-term bw sampling interval is done. Estimate whether we're policed. */
static  __always_inline void bbr_lt_bw_interval_done(struct sock *sk, __u32 bw)
{
	struct bbr *bbr = inet_csk_ca(sk);
	__u32 diff;

	if (bbr->lt_bw) {  /* do we have bw from a previous interval? */
		/* Is new bw close to the lt_bw from the previous interval? */
		int d = bw - bbr->lt_bw;
		diff = abs(d);
		if ((diff * BBR_UNIT <= bbr_lt_bw_ratio * bbr->lt_bw) ||
		    (bbr_rate_bytes_per_sec(sk, diff, BBR_UNIT) <=
		     bbr_lt_bw_diff)) {
			/* All criteria are met; estimate we're policed. */
			bbr->lt_bw = (bw + bbr->lt_bw) >> 1;  /* avg 2 intvls */
			bbr->lt_use_bw = 1;
			bbr->pacing_gain = BBR_UNIT;  /* try to avoid drops */
			bbr->lt_rtt_cnt = 0;
			return;
		}
	}
	bbr->lt_bw = bw;
	bbr_reset_lt_bw_sampling_interval(sk);
}
/* Token-bucket traffic policers are common (see "An Internet-Wide Analysis of
 * Traffic Policing", SIGCOMM 2016). BBR detects token-bucket policers and
 * explicitly models their policed rate, to reduce unnecessary losses. We
 * estimate that we're policed if we see 2 consecutive sampling intervals with
 * consistent throughput and high packet loss. If we think we're being policed,
 * set lt_bw to the "long-term" average delivery rate from those 2 intervals.
 */
static void bbr_lt_bw_sampling(struct sock *sk, const struct rate_sample *rs)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct bbr *bbr = inet_csk_ca(sk);
	__u32 lost, delivered;
	__u64 bw;
	__u32 t;

	if (bbr->lt_use_bw) {	/* already using long-term rate, lt_bw? */
		if (bbr->mode == BBR_PROBE_BW && bbr->round_start &&
		    ++bbr->lt_rtt_cnt >= bbr_lt_bw_max_rtts) {
			bbr_reset_lt_bw_sampling(sk);    /* stop using lt_bw */
			bbr_reset_probe_bw_mode(sk);  /* restart gain cycling */
		}
		return;
	}

	/* Wait for the first loss before sampling, to let the policer exhaust
	 * its tokens and estimate the steady-state rate allowed by the policer.
	 * Starting samples earlier includes bursts that over-estimate the bw.
	 */
	if (!bbr->lt_is_sampling) {
		if (!rs->losses)
			return;
		bbr_reset_lt_bw_sampling_interval(sk);
		bbr->lt_is_sampling = true;
	}

	/* To avoid underestimates, reset sampling if we run out of data. */
	if (rs->is_app_limited) {
		bbr_reset_lt_bw_sampling(sk);
		return;
	}

	if (bbr->round_start)
		bbr->lt_rtt_cnt++;	/* count round trips in this interval */
	if (bbr->lt_rtt_cnt < bbr_lt_intvl_min_rtts)
		return;		/* sampling interval needs to be longer */
	if (bbr->lt_rtt_cnt > 4 * bbr_lt_intvl_min_rtts) {
		bbr_reset_lt_bw_sampling(sk);  /* interval is too long */
		return;
	}

	/* End sampling interval when a packet is lost, so we estimate the
	 * policer tokens were exhausted. Stopping the sampling before the
	 * tokens are exhausted under-estimates the policed rate.
	 */
	if (!rs->losses)
		return;

	/* Calculate packets lost and delivered in sampling interval. */
	lost = tp->lost - bbr->lt_last_lost;
	delivered = tp->delivered - bbr->lt_last_delivered;
	/* Is loss rate (lost/delivered) >= lt_loss_thresh? If not, wait. */
	if (!delivered || (lost << BBR_SCALE) < bbr_lt_loss_thresh * delivered)
		return;

	/* Find average delivery rate in this sampling interval. */
	t = div64_u64(tp->delivered_mstamp, USEC_PER_MSEC) - bbr->lt_last_stamp;
	if ((int)t < 1)
		return;		/* interval is less than one ms, so wait */
	/* Check if can multiply without overflow */
	if (t >= ~0U / USEC_PER_MSEC) {
		bbr_reset_lt_bw_sampling(sk);  /* interval too long; reset */
		return;
	}
	t *= USEC_PER_MSEC;
	bw = (__u64)delivered * BW_UNIT;
	bw = div64_u64(bw, (__u64)t);
	bbr_lt_bw_interval_done(sk, (__u32)bw);
}
/* Estimate the bandwidth based on how fast packets are delivered */
static void bbr_update_bw(struct sock *sk, const struct rate_sample *rs)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct bbr *bbr = inet_csk_ca(sk);
	__u64 bw;

	bbr->round_start = 0;
	if (rs->delivered < 0 || rs->interval_us <= 0)
		return; /* Not a valid observation */

	/* See if we've reached the next RTT */
	if (!before(rs->prior_delivered, bbr->next_rtt_delivered)) {
		bbr->next_rtt_delivered = tp->delivered;
		bbr->rtt_cnt++;
		bbr->round_start = 1;
		bbr->packet_conservation = 0;
	}

	bbr_lt_bw_sampling(sk, rs);

	/* Divide delivered by the interval to find a (lower bound) bottleneck
	 * bandwidth sample. Delivered is in packets and interval_us in uS and
	 * ratio will be <<1 for most connections. So delivered is first scaled.
	 */
	bw = div64_u64((__u64)rs->delivered * BW_UNIT, rs->interval_us);

	/* If this sample is application-limited, it is likely to have a very
	 * low delivered count that represents application behavior rather than
	 * the available network rate. Such a sample could drag down estimated
	 * bw, causing needless slow-down. Thus, to continue to send at the
	 * last measured network rate, we filter out app-limited samples unless
	 * they describe the path bw at least as well as our bw model.
	 *
	 * So the goal during app-limited phase is to proceed with the best
	 * network rate no matter how long. We automatically leave this
	 * phase when app writes faster than the network can deliver :)
	 */
	if (!rs->is_app_limited || bw >= bbr_max_bw(sk)) {
		/* Incorporate new sample into our max bw filter. */
		my_minmax_running_max(&bbr->bw, bbr_bw_rtts, bbr->rtt_cnt, bw);
	}
}
/* Estimates the windowed max degree of ack aggregation.
 * This is used to provision extra in-flight data to keep sending during
 * inter-ACK silences.
 *
 * Degree of ack aggregation is estimated as extra data acked beyond expected.
 *
 * max_extra_acked = "maximum recent excess data ACKed beyond max_bw * interval"
 * cwnd += max_extra_acked
 *
 * Max extra_acked is clamped by cwnd and bw * bbr_extra_acked_max_us (100 ms).
 * Max filter is an approximate sliding window of 5-10 (packet timed) round
 * trips.
 */
static void bbr_update_ack_aggregation(struct sock *sk,
				       const struct rate_sample *rs)
{
	__u32 epoch_us, expected_acked, extra_acked;
	struct bbr *bbr = inet_csk_ca(sk);
	struct tcp_sock *tp = tcp_sk(sk);

	if (!bbr_extra_acked_gain || rs->acked_sacked <= 0 ||
	    rs->delivered < 0 || rs->interval_us <= 0)
		return;

	if (bbr->round_start) {
		bbr->extra_acked_win_rtts = min(0x1F,
						bbr->extra_acked_win_rtts + 1);
		if (bbr->extra_acked_win_rtts >= bbr_extra_acked_win_rtts) {
			bbr->extra_acked_win_rtts = 0;
			bbr->extra_acked_win_idx = bbr->extra_acked_win_idx ?
						   0 : 1;
			if(bbr->extra_acked_win_idx ==0){
				bbr->extra_acked[0] = 0;
			}else{
				bbr->extra_acked[1] = 0;
			}
		}
	}

	/* Compute how many packets we expected to be delivered over epoch. */
	epoch_us = tcp_stamp_us_delta(tp->delivered_mstamp,
				      bbr->ack_epoch_mstamp);
	expected_acked = ((__u64)bbr_bw(sk) * epoch_us) / BW_UNIT;

	/* Reset the aggregation epoch if ACK rate is below expected rate or
	 * significantly large no. of ack received since epoch (potentially
	 * quite old epoch).
	 */
	if (bbr->ack_epoch_acked <= expected_acked ||
	    (bbr->ack_epoch_acked + rs->acked_sacked >=
	     bbr_ack_epoch_acked_reset_thresh)) {
		bbr->ack_epoch_acked = 0;
		bbr->ack_epoch_mstamp = tp->delivered_mstamp;
		expected_acked = 0;
	}

	/* Compute excess data delivered, beyond what was expected. */
	bbr->ack_epoch_acked = min((__u32) 0xFFFFF,
				     (__u32)(bbr->ack_epoch_acked + rs->acked_sacked));
	extra_acked = bbr->ack_epoch_acked - expected_acked;
	extra_acked = min(extra_acked, tp->snd_cwnd);
	if(bbr->extra_acked_win_idx==0){
		if (extra_acked > bbr->extra_acked[0]){
			bbr->extra_acked[0] = extra_acked;
		}
	}else{
		if (extra_acked > bbr->extra_acked[1]){
			bbr->extra_acked[1] = extra_acked;
		}
	}
}
/* Estimate when the pipe is full, using the change in delivery rate: BBR
 * estimates that STARTUP filled the pipe if the estimated bw hasn't changed by
 * at least bbr_full_bw_thresh (25%) after bbr_full_bw_cnt (3) non-app-limited
 * rounds. Why 3 rounds: 1: rwin autotuning grows the rwin, 2: we fill the
 * higher rwin, 3: we get higher delivery rate samples. Or transient
 * cross-traffic or radio noise can go away. CUBIC Hystart shares a similar
 * design goal, but uses delay and inter-ACK spacing instead of bandwidth.
 */
static void bbr_check_full_bw_reached(struct sock *sk,
				      const struct rate_sample *rs)
{
	struct bbr *bbr = inet_csk_ca(sk);
	__u32 bw_thresh;

	if (bbr_full_bw_reached(sk) || !bbr->round_start || rs->is_app_limited)
		return;

	bw_thresh = (__u64)bbr->full_bw * bbr_full_bw_thresh >> BBR_SCALE;
	if (bbr_max_bw(sk) >= bw_thresh) {
		bbr->full_bw = bbr_max_bw(sk);
		bbr->full_bw_cnt = 0;
		return;
	}
	++bbr->full_bw_cnt;
	bbr->full_bw_reached = bbr->full_bw_cnt >= bbr_full_bw_cnt;
}
/* If pipe is probably full, drain the queue and then enter steady-state. */
static void bbr_check_drain(struct sock *sk, const struct rate_sample *rs)
{
	struct bbr *bbr = inet_csk_ca(sk);

	if (bbr->mode == BBR_STARTUP && bbr_full_bw_reached(sk)) {
		bbr->mode = BBR_DRAIN;	/* drain queue we created */
		tcp_sk(sk)->snd_ssthresh =
				bbr_inflight(sk, bbr_max_bw(sk), BBR_UNIT);
	}	/* fall through to check if in-flight is already small: */
	if (bbr->mode == BBR_DRAIN &&
	    bbr_packets_in_net_at_edt(sk, tcp_packets_in_flight(tcp_sk(sk))) <=
	    bbr_inflight(sk, bbr_max_bw(sk), BBR_UNIT))
		bbr_reset_probe_bw_mode(sk);  /* we estimate queue is drained */
}

static __always_inline void bbr_check_probe_rtt_done(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct bbr *bbr = inet_csk_ca(sk);

	if (!(bbr->probe_rtt_done_stamp &&
	      after(tcp_jiffies32, bbr->probe_rtt_done_stamp)))
		return;

	bbr->min_rtt_stamp = tcp_jiffies32;  /* wait a while until PROBE_RTT */
	tp->snd_cwnd = max(tp->snd_cwnd, bbr->prior_cwnd);
	bbr_reset_mode(sk);
}
/* The goal of PROBE_RTT mode is to have BBR flows cooperatively and
 * periodically drain the bottleneck queue, to converge to measure the true
 * min_rtt (unloaded propagation delay). This allows the flows to keep queues
 * small (reducing queuing delay and packet loss) and achieve fairness among
 * BBR flows.
 *
 * The min_rtt filter window is 10 seconds. When the min_rtt estimate expires,
 * we enter PROBE_RTT mode and cap the cwnd at bbr_cwnd_min_target=4 packets.
 * After at least bbr_probe_rtt_mode_ms=200ms and at least one packet-timed
 * round trip elapsed with that flight size <= 4, we leave PROBE_RTT mode and
 * re-enter the previous mode. BBR uses 200ms to approximately bound the
 * performance penalty of PROBE_RTT's cwnd capping to roughly 2% (200ms/10s).
 *
 * Note that flows need only pay 2% if they are busy sending over the last 10
 * seconds. Interactive applications (e.g., Web, RPCs, video chunks) often have
 * natural silences or low-rate periods within 10 seconds where the rate is low
 * enough for long enough to drain its queue in the bottleneck. We pick up
 * these min RTT measurements opportunistically with our min_rtt filter. :-)
 */
static void bbr_update_min_rtt(struct sock *sk, const struct rate_sample *rs)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct bbr *bbr = inet_csk_ca(sk);
	bool filter_expired;
	struct bbr_params* param = getBBRParam(sk);
	struct flow_param *flow = getFlowParam(param);

	/* Track min RTT seen in the min_rtt_win_sec filter window: */
	
	if(flow->mode == URGENT){
		filter_expired = after(tcp_jiffies32,
			       bbr->min_rtt_stamp + bbr_probe_rtt_win_urgent_sec * HZ);
	}else{
		filter_expired = after(tcp_jiffies32,
			       bbr->min_rtt_stamp + bbr_min_rtt_win_sec * HZ);
	}
	if (rs->rtt_us >= 0 &&
	    (rs->rtt_us < bbr->min_rtt_us ||
	     (filter_expired && !rs->is_ack_delayed))) {
		bbr->min_rtt_us = rs->rtt_us;
		bbr->min_rtt_stamp = tcp_jiffies32;
	}

	if (bbr_probe_rtt_mode_ms > 0 && filter_expired &&
	    !bbr->idle_restart && bbr->mode != BBR_PROBE_RTT) {
		bbr->mode = BBR_PROBE_RTT;  /* dip, drain queue */
		bbr_save_cwnd(sk);  /* note cwnd so we can restore it */
		bbr->probe_rtt_done_stamp = 0;
	}

	if (bbr->mode == BBR_PROBE_RTT) {
		//TTTTOOOOOOOOOOOOOOOO
		/* Ignore low rate samples during this mode. */
		param->app_limited =
			(tp->delivered + tcp_packets_in_flight(tp)) ? : 1;
		/* Maintain min packets in flight for max(200 ms, 1 round). */
		if (!bbr->probe_rtt_done_stamp &&
		    tcp_packets_in_flight(tp) <= bbr_probe_rtt_cwnd(sk) ) {
			bbr->probe_rtt_done_stamp = tcp_jiffies32 + bbr_probe_rtt_mode_ms;
			bbr->probe_rtt_round_done = 0;
			bbr->next_rtt_delivered = tp->delivered;
		} else if (bbr->probe_rtt_done_stamp) {
			if (bbr->round_start)
				bbr->probe_rtt_round_done = 1;
			if (bbr->probe_rtt_round_done)
				bbr_check_probe_rtt_done(sk);
		}
	}
	/* Restart after idle ends only once we process a new S/ACK for data */
	if (rs->delivered > 0)
		bbr->idle_restart = 0;
}
static void bbr_update_gains(struct sock *sk)
{
	struct bbr *bbr = inet_csk_ca(sk);
 	unsigned long long curtime;
	curtime = bpf_ktime_get_ns();
	struct bbr_params* param = getBBRParam(sk);

	__u16 sport = sk->__sk_common.skc_num;
	switch (bbr->mode) {
	case BBR_STARTUP:
		bbr->pacing_gain = rateGain(sk,param,bbr_high_gain);
		bbr->cwnd_gain	 = rateGain(sk,param,bbr_high_gain);
		if (sport == 80){
		bpf_printk( "enter BBR_STARTUP dport: %u, cwnd_gain: %u\n", 
		sk->__sk_common.skc_dport,bbr->cwnd_gain);
		}

		break;
	case BBR_DRAIN:
		bbr->pacing_gain = bbr_drain_gain;	/* slow, to drain */
		bbr->cwnd_gain	 = rateGain(sk,param,bbr_high_gain);	/* keep cwnd */
		break;
	case BBR_PROBE_BW:
		if(bbr->lt_use_bw){
			bbr->pacing_gain = BBR_UNIT;
		}else {
			if(bbr->cycle_idx ==0){
				bbr->pacing_gain = rateGain(sk,param,bbr_pacing_gain[0]);
			}
			else if (bbr->cycle_idx ==1){
				bbr->pacing_gain = bbr_pacing_gain[1];
			}else{
				bbr->pacing_gain = BBR_UNIT;
			}
		}
		if (sport == 80){
		bpf_printk( "enter BBR_PROBE_BW dport: %u, TIME: %u\n", 
		sk->__sk_common.skc_dport,curtime);
		}
		break;
	case BBR_PROBE_RTT:
		bbr->pacing_gain = BBR_UNIT;
		bbr->cwnd_gain	 = BBR_UNIT;
		if (sport == 80){
		bpf_printk( "enter BBR_PROBE_RTT dport: %u, TIME: %u\n", 
		sk->__sk_common.skc_dport,curtime);
		}	
		break;
	default:
		bpf_printk( "BBR bad mode: %u\n", bbr->mode);
		break;
	}
}
/* Update (most of) our congestion signals: track the recent rate and volume of
 * delivered data, presence of loss, and EWMA degree of ECN marking.
 */
static void bbr2_update_congestion_signals(
	struct sock *sk, const struct rate_sample *rs)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct bbr *bbr = inet_csk_ca(sk);
	//__u64 bw;
	struct bbr_params* param = getBBRParam(sk);
	struct flow_param* flow = getFlowParam(param);
	__u16 sport = sk->__sk_common.skc_num;	

	if(flow !=NULL && sport == 80){
		bpf_printk("flow param rate %ld flow_key%u \n",flow->target_rate,param->flow_key);
	}

	param->loss_round_start = false;
	if (rs->interval_us <= 0)
		return; /* Not a valid observation */
	// bw = ctx->sample_bw;

	// if (!rs->is_app_limited || bw >= bbr_max_bw(sk))
	// 	bbr2_take_bw_hi_sample(sk, bw);

	param->loss_in_round |= (rs->losses > 0);
	if (sport == 80){
		bpf_printk( "update congestion signals loss round start dport: %u, loss in round: %u \n",sk->__sk_common.skc_dport, param->loss_in_round);
	}

	/* Update rate and volume of delivered data from latest round trip: */
	if (before(rs->prior_delivered, param->loss_round_delivered))
		return;		/* skip the per-round-trip updates */
	/* Now do per-round-trip updates. */
	
	param->loss_round_delivered = tp->delivered; 
	param->loss_round_start = true;
	// param->prior_sample_lost = tp->lost_out;
	// param->prior_sample_delivered = tp->delivered;
	// param->is_app_limited = rs->is_app_limited;
	/* Update windowed "latest" (single-round-trip) filters. */
	param->loss_in_round = 0;
	
}

static void bbr_update_model(struct sock *sk, const struct rate_sample *rs)
{
	bbr2_update_congestion_signals(sk, rs);
	bbr_update_bw(sk, rs);
	bbr_update_ack_aggregation(sk, rs);
	bbr_update_cycle_phase(sk, rs);
	bbr2_check_loss_too_high_in_startup(sk, rs);
	bbr_check_full_bw_reached(sk, rs);
	bbr_check_drain(sk, rs);
	bbr_update_min_rtt(sk, rs);
	bbr_update_gains(sk);
}


#define BITS_PER_U64 (sizeof(__u64) * 8)

SEC("struct_ops/bbr_init")
void BPF_PROG(bbr_init, struct sock *sk)
{
	bpf_printk("==========bpf_bbr init\n");
	struct tcp_sock *tp = tcp_sk(sk);
	struct bbr *bbr = inet_csk_ca(sk);

	bbr->prior_cwnd = 0;
	tp->snd_ssthresh = TCP_INFINITE_SSTHRESH;
	bbr->rtt_cnt = 0;
	bbr->next_rtt_delivered = 0;
	bbr->prev_ca_state = TCP_CA_Open;
	bbr->packet_conservation = 0;

	bbr->probe_rtt_done_stamp = 0;
	bbr->probe_rtt_round_done = 0;
	bbr->min_rtt_us = tcp_min_rtt(tp);
	bbr->min_rtt_stamp = tcp_jiffies32;

	my_minmax_reset(&bbr->bw, bbr->rtt_cnt, 0);  /* init max bw to 0 */

	bbr->has_seen_rtt = 0;
	bbr_init_pacing_rate_from_rtt(sk);

	bbr->round_start = 0;
	bbr->idle_restart = 0;
	bbr->full_bw_reached = 0;
	bbr->full_bw = 0;
	bbr->full_bw_cnt = 0;
	bbr->cycle_mstamp = 0;
	bbr->cycle_idx = 0;
	bbr_reset_lt_bw_sampling(sk);
	bbr_reset_startup_mode(sk);

	bbr->ack_epoch_mstamp = tp->tcp_mstamp;
	bbr->ack_epoch_acked = 0;
	bbr->extra_acked_win_rtts = 0;
	bbr->extra_acked_win_idx = 0;
	bbr->extra_acked[0] = 0;
	bbr->extra_acked[1] = 0;

}


static void bbr_update_round_start(struct sock *sk,
		const struct rate_sample *rs)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct bbr *bbr = inet_csk_ca(sk);

	struct bbr_params* param = getBBRParam(sk);

	bbr->round_start = 0;

	/* See if we've reached the next RTT */
	if (rs->interval_us > 0 &&
	    !before(rs->prior_delivered, bbr->next_rtt_delivered)) {
		bbr->next_rtt_delivered = tp->delivered;
		bbr->round_start = 1;
		param->prior_sample_lost = tp->lost_out;
		param->prior_sample_delivered = tp->delivered;
		param->is_app_limited = rs->is_app_limited;
		param->loss_in_round = 0;

	}
}
/* No prefix in SEC will also work.
 * The remaining tcp-cubic functions have an easier way.
 */
SEC("no-sec-prefix-bbr_main")
void BPF_PROG(bbr_main, struct sock *sk, const struct rate_sample *rs)
{
	struct bbr *bbr = inet_csk_ca(sk);
	__u32 bw;
	// test
	__u16 sport = sk->__sk_common.skc_num;
	
	__u16 dport = sk->__sk_common.skc_dport;
	
	//struct bbr_params *param = NULL;

	// struct bbr_params *param = bpf_map_lookup_elem(&paramMap, &dport);
	// if (!param){
	// 		struct bbr_params newParam = {0,0,true,0,mod,0,0,0,0,0,0,0,false};
	// 		bpf_map_update_elem(&paramMap, &dport, &newParam, BPF_ANY);
	// 		bpf_printk( "do not get bbr param!!!!!\n");
	// }else{
	// 		bpf_printk( "enter bbr main dport: %u, param_mod: %u, loss_in_round:%u\n", dport,param->mod,param->loss_in_round);
	// 		//bpf_printk( "do  get bbr param!!!!!\n");
	// }

	bbr_update_round_start(sk, rs);
	//end test
	bbr_update_model(sk, rs);
	bw = bbr_bw(sk);
	bbr_set_pacing_rate(sk, bw, bbr->pacing_gain);
	bbr_set_cwnd(sk, rs, rs->acked_sacked, bw, bbr->cwnd_gain);

}

static void bbr2_reset_congestion_signals(struct sock *sk)
{
	struct bbr_params* param = getBBRParam(sk);
	param->loss_in_round = 0;
	param->loss_round_start = false;
}



static void bbr2_start_bw_probe_down(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct bbr *bbr = inet_csk_ca(sk);
	struct bbr_params* param = getBBRParam(sk);

	bbr2_reset_congestion_signals(sk);
	bbr->cycle_mstamp = tp->tcp_mstamp;		/* start wall clock */
	bbr->next_rtt_delivered = tp->delivered;

	bbr->mode = BBR_PROBE_BW;
	bbr->cycle_idx =1;
	bbr->pacing_gain = bbr_pacing_gain[1];
}

/* How much do we want in flight? Our BDP, unless congestion cut cwnd. */
static __u32 bbr2_target_inflight(struct sock *sk)
{
	__u32 bdp = bbr_inflight(sk, bbr_bw(sk), BBR_UNIT);

	return min(bdp, tcp_sk(sk)->snd_cwnd);
}

static void bbr2_handle_inflight_too_high(struct sock *sk)
{
	struct bbr *bbr = inet_csk_ca(sk);
	struct tcp_sock *tp = tcp_sk(sk);
	const __u32 beta = bbr_beta;
	struct bbr_params* param = getBBRParam(sk);
	__u16 sport = sk->__sk_common.skc_num;	
	if (sport == 80){
		bpf_printk( "enter bbr2_handle_inflight_too_high \n");
	}

	if (!param->is_app_limited){
		param->advice_cwnd = max((__u32)tp->packets_out,
					 (__u32)((__u64)bbr2_target_inflight(sk) *
					 (BBR_UNIT - beta) >> BBR_SCALE));
		param->is_used_advice_cwnd = false;
}
	
	if (bbr->mode == BBR_PROBE_BW && bbr->pacing_gain == bbr_pacing_gain[0])
		bbr2_start_bw_probe_down(sk);
}

static bool bbr2_is_inflight_too_high(struct sock *sk)
{
	struct bbr_params* param = getBBRParam(sk);

	__u32 loss_thresh;

	if (param->sample_lost > 0 && param->delivered>0) {
		loss_thresh = (__u64)param->delivered * bbr_loss_thresh >>
				BBR_SCALE;
		__u16 sport = sk->__sk_common.skc_num;	
		if (sport == 80){
				bpf_printk( "enter bbr2_is_inflight_too_high dport: %u, sample_lost: %u , delivered: %u\n"
				,sk->__sk_common.skc_dport, param->sample_lost,param->delivered);
		}
		if (param->sample_lost > loss_thresh)
			return true;
	}

	return false;
}

static void bbr2_handle_queue_too_high_in_startup(struct sock *sk)
{
	struct bbr *bbr = inet_csk_ca(sk);
	struct bbr_params* param = getBBRParam(sk);

	bbr->full_bw_reached = 1;
	param->advice_cwnd = bbr_inflight(sk, bbr_max_bw(sk), BBR_UNIT);
	param->is_used_advice_cwnd = false;
	__u16 sport = sk->__sk_common.skc_num;	
	if (sport == 80){
		bpf_printk( "enter bbr2_handle_queue_too_high_in_startup dport: %u, advice_cwnd: %u \n"
		,sk->__sk_common.skc_dport, param->advice_cwnd);
	}
}
/* Exit STARTUP based on loss rate > 1% and loss gaps in round >= N. Wait until
 * the end of the round in recovery to get a good estimate of how many packets
 * have been lost, and how many we need to drain with a low pacing rate.
 */
static void bbr2_check_loss_too_high_in_startup(struct sock *sk,
					       const struct rate_sample *rs)
{
	struct bbr *bbr = inet_csk_ca(sk);
	struct bbr_params* param = getBBRParam(sk);
	struct flow_param *flow = getFlowParam(param);

	__u16 sport = sk->__sk_common.skc_num;	
	if (sport == 80){
		bpf_printk( "enter check loss too high dport: %u, mod: %u \n",sk->__sk_common.skc_dport, flow->mode);
	}
	if(flow->mode == URGENT)
		return;
	if (bbr_full_bw_reached(sk))
		return;

	/* For STARTUP exit, check the loss rate at the end of each round trip
	 * of Recovery episodes in STARTUP. We check the loss rate at the end
	 * of the round trip to filter out noisy/low loss and have a better
	 * sense of inflight (extent of loss), so we can drain more accurately.

	 * startup
	 */
	if (rs->losses && param->loss_events_in_round < 0xf)
		param->loss_events_in_round++;  /* update saturating counter */
	if (sport == 80){
			bpf_printk( "enter bbr2_check_loss_too_high_in_startup dport: %u, loss_cnt:  %u ;rs_loss %u \n"
			,sk->__sk_common.skc_dport, param->loss_events_in_round,rs->losses);
	}
	if (param->loss_round_start &&
	    inet_csk(sk)->icsk_ca_state == TCP_CA_Recovery &&
	    param->loss_events_in_round >= bbr_full_loss_cnt&& bbr2_is_inflight_too_high(sk)) {
			if (sport == 80){
				bpf_printk( "enter loss too high dport: %u, loss_cnt: %u \n"
				,sk->__sk_common.skc_dport, param->loss_events_in_round);
		}
		bbr2_handle_queue_too_high_in_startup(sk);
		return;
	}
	if (param->loss_round_start)
		param->loss_events_in_round = 0;
}


/* Or simply use the BPF_STRUCT_OPS to avoid the SEC boiler plate. */
__u32 BPF_STRUCT_OPS(bbr_sndbuf_expand, struct sock *sk)
{
	return 3;
}

static void bbr2_skb_marked_lost(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct bbr *bbr = inet_csk_ca(sk);
	struct bbr_params* param = getBBRParam(sk);
	struct flow_param *flow = getFlowParam(param);

	/* Capture "current" data over the full round trip of loss,
	 * to have a better chance to see the full capacity of the path.
	*/
	if (!param->loss_in_round)  /* first loss in this round trip? */
		param->loss_round_delivered = tp->delivered;  /* set round trip */
	param->loss_in_round = 1;

	param->delivered = tp->delivered - param->prior_sample_delivered;
	param->sample_lost= tp->lost - param->prior_sample_lost;
	__u16 sport = sk->__sk_common.skc_num;	
	if (sport == 80){
		bpf_printk( "enter bbr2_skb_marked_lost dport: %u, delivered: %u , lost: %u \n"
		,sk->__sk_common.skc_dport, param->delivered,param->sample_lost);
	}
	if (flow->mode == NORMAL && bbr2_is_inflight_too_high(sk) ) {
		bbr2_handle_inflight_too_high(sk);
	}
}
__u32 BPF_STRUCT_OPS(bbr_undo_cwnd, struct sock *sk)
{
	struct bbr *bbr = inet_csk_ca(sk);
	struct bbr_params* param = getBBRParam(sk);
	struct flow_param *flow = getFlowParam(param);

	bbr->full_bw = 0;   /* spurious slow-down; reset full pipe detection */
	bbr->full_bw_cnt = 0;
	bbr_reset_lt_bw_sampling(sk);
	if(flow->mode ==NORMAL){
		return bbr->prior_cwnd;
	}
	return tcp_sk(sk)->snd_cwnd;
}



#define GSO_MAX_SIZE		65536



__u32 BPF_STRUCT_OPS(bbr_ssthresh, struct sock *sk)
{
	bbr_save_cwnd(sk);
	struct tcp_sock *tp = tcp_sk(sk);

	__u16 sport = sk->__sk_common.skc_num;	
	if (sport == 80){
		bpf_printk( "enter bbr_ssthresh dport: %u, lost: %u \n",sk->__sk_common.skc_dport, tp->lost);
	}
	bbr2_skb_marked_lost(sk);
	return tcp_sk(sk)->snd_ssthresh;

}

void BPF_STRUCT_OPS(bbr_set_state, struct sock *sk, __u8 new_state)
{
		bpf_printk("==========bbr_set_state\n");
		struct bbr *bbr = inet_csk_ca(sk);

	if (new_state == TCP_CA_Loss) {
		struct rate_sample rs = { .losses = 1 };

		bbr->prev_ca_state = TCP_CA_Loss;
		bbr->full_bw = 0;
		bbr->round_start = 1;	/* treat RTO like end of a round */
		bbr_lt_bw_sampling(sk, &rs);
	}
}
__u32 BPF_STRUCT_OPS(new_bbr_min_tso_segs, struct sock *sk)
{
	struct bbr_params* param = getBBRParam(sk);

	return param->pacing_rate < (bbr_min_tso_rate >> 3) ? 1 : 2;
}

SEC("struct_ops/tcp_reno_cong_avoid")
void BPF_PROG(tcp_reno_cong_avoid, struct sock *sk, __u32 ack, __u32 acked)
{
	struct tcp_sock *tp = tcp_sk(sk);

	if (!tcp_is_cwnd_limited(sk))
		return;

	/* In "safe" area, increase. */
	if (tcp_in_slow_start(tp)) {
		acked = tcp_slow_start(tp, acked);
		if (!acked)
			return;
	}
	/* In dangerous area, increase slowly. */
	tcp_cong_avoid_ai(tp, tp->snd_cwnd, acked);
}

SEC(".struct_ops")
struct tcp_congestion_ops bbr = {
	.init		= (void *)bbr_init,
	.cong_control	= (void *)bbr_main,
	.cong_avoid	= (void *)tcp_reno_cong_avoid,
	.sndbuf_expand	= (void *)bbr_sndbuf_expand,
	.undo_cwnd	= (void *)bbr_undo_cwnd,
	.cwnd_event	= (void *)bbr_cwnd_event,
	.ssthresh	= (void *)bbr_ssthresh,
	.min_tso_segs	= (void *)new_bbr_min_tso_segs,
	.set_state	= (void *)bbr_set_state,
	.name		= "bpf_bbr",
};
