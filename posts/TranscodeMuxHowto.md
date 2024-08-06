[`ffmpeg`](https://github.com/FFmpeg/FFmpeg) is FLOSS (no cost), plus is the best executable to transcode/trim/demux/mux. `ffmpeg` is on [Windows](https://wikipedia.org/wiki/Windows)/[Linux](https://wikipedia.org/wiki/Linux)/[Android OS](https://wikipedia.org/wiki/Android_(operating_system))/[iOS](https://wikipedia.org/wiki/iOS)/[OSX](https://wikipedia.org/wiki/OSX).

[[This post allows all uses](https://swudususuwu.substack.com/p/ffmpeg-is-floss-no-cost-plus-is-the)]

[_Video Transcoder_ - Apps on Google Play](https://play.google.com/store/apps/details?id=protect.videoeditor) (a visual interface to `ffmpeg`) was cool versus most “_video editor_” apps -- but is not available for new versions of _Android OS_, can not loop (just has trim + convert (which can act as demux) + resize + compress), is slow (can not pass `-c copy` to `ffmpeg`, thus always reincodes inputs.)

Now use [_FFmpeg Media Encoder_ - Apps on Google Play](https://play.google.com/store/apps/details?id=com.silentlexx.ffmpeggui) (_SilentLexx_) with much success. It has a visual interface to `fmpeg` but can process commands from text. Alternative (have not used): [FFmpeg - Apps on Google Play](https://play.google.com/store/apps/details?id=com.crossplat.ffmpegmobile) (FFmpeg from CrossPlat).

For misc Linuxes (suchas [Android-Termux](https://play.google.com/store/apps/details?id=com.termux)); `apt-get install ffmpeg && termux-setup-storage`. For iOS; [https://shaunhevey.com/posts/how-to-use-ffmpeg-on-ios/](https://shaunhevey.com/posts/how-to-use-ffmpeg-on-ios/). For OSX; `brew install ffmpeg --with-fdk-aac --with-ffplay --with-freetype --with-libass --with-libvorbis --with-libvpx --with-opus` (or [alternatives](https://superuser.com/questions/624561/install-ffmpeg-on-os-x/624562#624562)). For Windows; [FFmpeg - Official app in the Microsoft Store](https://apps.microsoft.com/detail/9nb2flx7x7wg?hl=en-za&gl=ZA).

[*Notice*: have moved default paths `/Music/` to `/Sounds/`, `/Movies/` to `/Visuals/`]

[*Notice*: Can use examples with _FFmpeg Media Encoder_ or _Termux_ as-is (use absolute paths).]

Example `visuals.mp4` was *4gb*, to compress to *224mb* used `ffmpeg -i "/storage/emulated/0/Visuals/screen-20240629-045526.mp4" -framerate 30 -c:v libx264 -crf 32 -preset slower "/storage/emulated/0/Visuals/visuals.mp4"`

The `libx264` codec compresses visuals best. `-preset slower` instructs it to compress more. You can replace `-crf 32` with `-b:v 2m` to set an exact goal of “compress to *2mbps*”.

[*Notice*: On some devices, _Android OS_’s permissions require to output to `/storage/emulated/0/Download/`]

Suppose you want to mux `sounds.mp4` with `visuals.mp4`,

but you want to skip `sounds.mp4`’s *4* second intro, plus limit output to *2* minutes:

To demux sounds, pass `-ss 4` to skip *4* seconds, pass `-t 2:00` to output *2* minutes, pass `-map 0:a:0` (zero-indexed) to demux first input as sounds, pass `-c copy` for instant process, output as `.m4a`: `ffmpeg -i "/storage/emulated/0/Download/sounds.mp4 -ss 4 -t 2:00 -map 0:a:0 -c copy "/storage/emulated/0/Sounds/demux.m4a"`

Now `sounds.m4a` is *2* minutes, but `visuals.m4a` is much longer; pass `-stream_loop -1` to mux sounds as loop  to match `visuals.mp4`:

    `fmpeg` -i "/storage/emulated/0/Visuals/visuals.mp4" -stream_loop -1 -i "/storage/emulated/0/Sounds/demux.m4a" -map 0:v:0 -c copy -map 1:a:0 -shortest "/storage/emulated/0/Visuals/mux.mp4" 

Suppose you want the mix the sounds from `visuals.mp4` with the loop from `sounds.mp4`:

    `fmpeg` -i "/storage/emulated/0/Visuals/visuals.mp4" -stream_loop -1 -i "/storage/emulated/0/Sounds/demux.m4a" -map 0:a:0 -map 1:a:0 -filter_complex amix=inputs=2:duration=shortest "/storage/emulated/0/Sounds/demux2.m4a" 
     
    `fmpeg` -i "/storage/emulated/0/Visuals/visuals.mp4" -i "/storage/emulated/0/Sounds/demux2.m4a" -map 0:v:0 -c copy -map 1:a:0 -shortest "/storage/emulated/0/Visuals/mux2.mp4"

[*Notice*: `-c copy` is not compatible with `-filter_complex`; unless you want to reincode the visuals (slow), is 2 steps to do this]

Suppose you wish to produce a *10fps* HD `.gif` from the first *24* seconds of `visual.mp4`:
`ffmpeg -i "/storage/emulated/0/Visuals/visual.mp4" -map 0:v:0 -pix_fmt rgb24 -r 10 -s 1920x1080 -t 24 "/storage/emulated/0/Visuals/visual.gif"`

Lists of commands which `fmpeg` can use;
[ffmpeg Documentation](https://ffmpeg.org/ffmpeg.html)
[complete list of `fmpeg` flags / commands](https://gist.github.com/tayvano/6e2d456a9897f55025e25035478a3a50#file-gistfile1-txt)

How to use extra tools which `ffmpeg`'s _GPLv2_ version has; [https://github.com/FFmpeg/FFmpeg/blob/master/LICENSE.md](https://github.com/FFmpeg/FFmpeg/blob/master/LICENSE.md)

`mux.mp4`/`mux2.mp4` syntax was used to produce:
[https://www.youtube.com/watch?v=zcqRmYUQKM8](https://www.youtube.com/watch?v=zcqRmYUQKM8)
[https://www.youtube.com/watch?v=YFgRW58mbG4](https://www.youtube.com/watch?v=YFgRW58mbG4)

`visual.gif` syntax was used to produce:
[https://www.deviantart.com/swudususuwu/art/BUD-Robos-hold-you-loop-v0-4-3-2-S-Simulator-1004148092](https://www.deviantart.com/swudususuwu/art/BUD-Robos-hold-you-loop-v0-4-3-2-S-Simulator-1004148092)
[https://www.deviantart.com/swudususuwu/art/Sakura-School-Simulator-howto-use-robot-props-loop-1019774750](https://www.deviantart.com/swudususuwu/art/Sakura-School-Simulator-howto-use-robot-props-loop-1019774750)

