# shaka player in Themis

Please check shaka player's official dependency-related installation:

https://shaka-player-demo.appspot.com/docs/api/tutorial-welcome.html

After you have installed the dependencies, you can start compiling shaka player with the following command：

```shell
cd shaka-player
python build/all.py
```

After the compilation is complete, you can see the myapp.js and test.html files, modify the manifestUri variable in the myapp.js file to point to the m3u8 file deployed on your server.

```javascript
// for example
const manifestUri =
'https://x.x.x.x/food/food.m3u8';
```

Then open test.html with your chrome to watch the video :)
