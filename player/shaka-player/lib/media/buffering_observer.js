/*! @license
 * Shaka Player
 * Copyright 2016 Google LLC
 * SPDX-License-Identifier: Apache-2.0
 */

goog.provide('shaka.media.BufferingObserver');


/**
 * The buffering observer watches how much content has been buffered and raises
 * events when the state changes (enough => not enough or vice versa).
 *
 * @final
 */
shaka.media.BufferingObserver = class {
  /**
   * @param {number} thresholdWhenStarving
   * @param {number} thresholdWhenSatisfied
   */
  constructor(thresholdWhenStarving, thresholdWhenSatisfied) {
    const State = shaka.media.BufferingObserver.State;

    /** @private {shaka.media.BufferingObserver.State} */
    this.previousState_ = State.SATISFIED;

    /** @private {!Map.<shaka.media.BufferingObserver.State, number>} */
    this.thresholds_ = new Map()
        .set(State.SATISFIED, thresholdWhenSatisfied)
        .set(State.STARVING, thresholdWhenStarving);
    /** @type {number} */
    this.mode = 1;
  }

  /**
   * @param {number} thresholdWhenStarving
   * @param {number} thresholdWhenSatisfied
   */
  setThresholds(thresholdWhenStarving, thresholdWhenSatisfied) {
    const State = shaka.media.BufferingObserver.State;
    this.thresholds_
        .set(State.SATISFIED, thresholdWhenSatisfied)
        .set(State.STARVING, thresholdWhenStarving);
  }

  /**
   * Update the observer by telling it how much content has been buffered (in
   * seconds) and if we are buffered to the end of the presentation. If the
   * controller believes the state has changed, it will return |true|.
   *
   * @param {number} bufferLead
   * @param {boolean} bufferedToEnd
   * @return {boolean}
   */
  update(bufferLead, bufferedToEnd) {
    const State = shaka.media.BufferingObserver.State;

    /**
     * Our threshold for how much we need before we declare ourselves as
     * starving is based on whether or not we were just starving. If we
     * were just starving, we are more likely to starve again, so we require
     * more content to be buffered than if we were not just starving.
     *
     * @type {number}
     */
    const threshold = this.thresholds_.get(this.previousState_);

    const oldState = this.previousState_;
    const newState = (bufferedToEnd || bufferLead >= threshold) ?
                     (State.SATISFIED) :
                     (State.STARVING);
    // judging the mode
    this.mode = bufferLead <= 5 ? 1 : 2;
    // Save the new state now so that calls to |getState| from any callbacks
    // will be accurate.
    this.previousState_ = newState;

    // Return |true| only when the state has changed.
    return oldState != newState;
  }

  /**
   * Set which state that the observer should think playback was in.
   *
   * @param {shaka.media.BufferingObserver.State} state
   */
  setState(state) {
    this.previousState_ = state;
  }

  /**
   * Get the state that the observer last thought playback was in.
   *
   * @return {shaka.media.BufferingObserver.State}
   */
  getState() {
    return this.previousState_;
  }
};

/**
 * Rather than using booleans to communicate what state we are in, we have this
 * enum.
 *
 * @enum {number}
 */
shaka.media.BufferingObserver.State = {
  STARVING: 0,
  SATISFIED: 1,
};
