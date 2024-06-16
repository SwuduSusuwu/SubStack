Next class: have computers do most of central nervous system, such as thalamus, auditory cortex, visual cortices, homunculus
Parse inputs of 1024*1280@60fps (2.6gbps), output text at a few kbps, reproduce originals from text (with small losses.)

_Allows all uses._

For the most new sources, use programs such as [iSH](https://apps.apple.com/us/app/ish-shell/id1436902243) (for iOS) or [Termux](https://play.google.com/store/apps/details?id=com.termux) (for Android OS) to run this:

git clone https://github.com/SwuduSusuwu/SubStack.git
cd SubStack/cxx && ls

Pull requests should goto: https://github.com/SwuduSusuwu/SubStack/issues/2

[cxx/ClassResultList.cxx](https://github.com/SwuduSusuwu/SubStack/blob/trunk/cxx/ClassResultList.cxx) has correspondances to [neocortex](https://wikipedia.org/wiki/Neocortex). which is what humans use as databases.
[cxx/VirusAnalysis.cxx](https://github.com/SwuduSusuwu/SubStack/blob/trunk/cxx/VirusAnalysis.cxx) + [cxx/ConversationCns.cxx](https://github.com/SwuduSusuwu/SubStack/blob/trunk/cxx/ConversationCns.cxx)  has some correspondances to [Broca's area](https://wikipedia.org/wiki/Broca's_area) (produces language through recursive processes), [Wernicke’s area](https://wikipedia.org/wiki/Wernicke's_area) (parses languages through [recursive](https://wikipedia.org/wiki/recursion) processes), plus [hippocampus](https://wikipedia.org/wiki/Hippocampus) (integration to the neocortex + [imagination](https://wikipedia.org/wiki/Procedural_generation) through various regions).
[cxx/ClassCns.cxx](https://github.com/SwuduSusuwu/SubStack/blob/trunk/cxx/ClassCns.cxx) ([HSOM](https://github.com/CarsonScott/HSOM) + [apxr_run](https://github.com/Rober-t/apxr_run)) is just templates for general-purpose [emulations](https://wikipedia.org/wiki/emulation) of neural mass.
https://www.deviantart.com/dreamup has some equivalences to how [visual cortex](https://wikipedia.org/wiki/Visual_cortex) + Broca's area + hippocampus + text inputs = [texture generation](https://wikipedia.org/wiki/Procedural_generation) + [mesh generation](https://wikipedia.org/wiki/Mesh_generation) outputs.
To have autonomous robots produce all goods for us [ https://swudususuwu.substack.com/p/program-general-purpose-robots-autonomous ] would require [visual cortex](https://wikipedia.org/wiki/Visual_cortex) (parses inputs from [photoreceptors](https://wikipedia.org/wiki/Photoreceptors)) + [auditory cortex](https://wikipedia.org/wiki/Auditory_cortex) (parses inputs from [malleus](https://wikipedia.org/wiki/Malleus) + [cortical homunculus](https://wikipedia.org/wiki/Cortical_homunculus) (parses inputs from touch sensors) + [thalamus](https://wikipedia.org/wiki/Thalamus) (merges information from various classes of sensors, thus the robot balances + produces [maps](https://wikipedia.org/wiki/Map_(mathematics))) + [hippocampus](https://wikipedia.org/wiki/Hippocampus) (uses outputs from sensors to setup neocortex, plus, runs [inverses](https://wikipedia.org/wiki/Inverse_function) this for synthesis of new scenarios) + Wernicke's region/Broca's regions (recursive [language processes](https://wikipedia.org/wiki/Natural_language_processing))

Just as a human who watches a video performs the following tasks:
[Retinal nervous tissue](https://wikipedia.org/wiki/Retina) has raw [photons](https://wikipedia.org/wiki/Photons) as inputs, and [compresses](https://wikipedia.org/wiki/Visual_system) such into splines + edges + motion vectors (close to how computers produce [splines](https://wikipedia.org/wiki/splines) through [edge detection](https://wikipedia.org/wiki/edge_detection) plus do [motion estimation](https://wikipedia.org/wiki/motion_estimation), which is what the most advanced traditional codecs such as [x264](https://wikipedia.org/wiki/x264) do to compress)
passes millions/billions of those (through optic nerves) to the V1 visual cortex (as opposed to just dump those to a .mp4, which is what computers do),
which groups those to produce more [abstract](https://wikipedia.org/wiki/abstraction), [sparse](https://wikipedia.org/wiki/sparse_network), [compressed](https://wikipedia.org/wiki/compress) forms (close to a simulator's [meshes](https://wikipedia.org/wiki/mesh_generation) / [textures](https://wikipedia.org/wiki/image_textures) / [animations](https://wikipedia.org/wiki/animations)),
passes those to V1 [visual cortex](https://wikipedia.org/wiki/Visual_cortex),
which synthesizes those into more abstract datums (such as a simulator's specific instances of individual humans, tools, or houses),
and passes the most abstract (from V2 visual cortex) plus complex (from V1 visual cortex) to [hippocampus](https://wikipedia.org/wiki/Hippocampus) (which performs temporary storage tasks while active, and, at rest, encodes this to neocortex).
Just as humans can use the [neocortex](https://wikipedia.org/wiki/Neocortex)'s stored resources for synthesis of new animations/visuals,
so too could artificial central nervous systems (run on [CPU](https://wikipedia.org/wiki/CPU) or [GPU](https://wikipedia.org/wiki/GPU)) setup [synapses](https://wikipedia.org/wiki/synapses) to allow to compress gigabytes of visuals from videos into a few kilobytes of text (the hippocampus has dual uses, so can expand the compressed "text" back to good visuals).

2 routes to this:

    [Unsupervised CNS](https://wikipedia.org/wiki/Unsupervised_learning) (fitness function of synapses is just to compress as much as can, plus reproduce as much of originals as can for us; layout of synapses is somewhat based on human CNS). This allows to add a few paragraphs of text past the finish so this synthesizes hours of extra video for you.

    [Supervised CNS](https://wikipedia.org/wiki/Supervised_learning) (various [sub](https://wikipedia.org/wiki/Submodule)-CNS's for various stages of compression, with examples used to setup the synapses for those various stages to compress, such as "[raw](https://wikipedia.org/wiki/Binary_encoding) [bitmap](https://wikipedia.org/wiki/Bitmap) -> [Scalable Vector Graphics](https://wikipedia.org/wiki/Scalable_Vector_Graphics) + partial [texture](https://wikipedia.org/wiki/Image_texture) [synthesis](https://wikipedia.org/wiki/Procedural_generation)", "[video](https://wikipedia.org/wiki/Video) (vector of bitmaps) -> [motion estimation](https://wikipedia.org/wiki/Motion_estimation) vectors", "Scalable Vector Graphics/textures + [motion estimation](https://wikipedia.org/wiki/Motion_estimation) [vectors](https://wikipedia.org/wiki/Vector_calculus) -> [mesh generation](https://wikipedia.org/wiki/Mesh_generation) + [animation](https://wikipedia.org/wiki/Animation) + full [texture synthesis](https://wikipedia.org/wiki/Procedural_generation)", plus the [inverses](https://wikipedia.org/wiki/Inverse_function) to [decompress](https://wikipedia.org/wiki/Decompress)). This allows to add a few paragraphs of text past the finish so this synthesizes hours of extra video for you.

Humans process more complex experiences than just visual senses: humans also have layers of various [auditory cortex](https://wikipedia.org/wiki/Auditory_cortex) tissues, so that sound compresses, plus a [thalamus](https://wikipedia.org/wiki/Thalamus) (which merges your various senses, thus the hippocampus has both audio+visual to access and compress, which, for a computer, would be as if you could all speech + lip motions down to the subtitles ([.ass](https://wikipedia.org/wiki/.ass))).

Sources: https://wikipedia.org/wiki/Visual_cortex, [Neuroscience for Dummies](https://www.amazon.com/Neuroscience-Dummies-Frank-Amthor/dp/1394171218) plus various such books

Not sure if the arxiv.org articles[1][2] are about this, but if not, could produce this for us if someone sponsors.

    [1] [A Computationally Efficient Neural Video Compression Accelerator Based on a Sparse CNN-Transformer Hybrid Network](https://arxiv.org/html/2312.10716v1)

    [2] [Advances In Video Compression System Using Deep Neural Network: A Review And Case Studies](https://arxiv.org/abs/2101.06341)

Because the arxiv.org pages do not list compression ratios, have doubts, but if someone has done this, won't waste resources to produce what someone else has.
Expected compression ratios: parse inputs of 1024*1280@60fps (2.6gbps), output text at approx 2kbps, reproduce originals from text (with small losses,) so ratio is approx "2,600,000 to 2" (as opposed to x264 which is at best “700 to 2”).

You could input such as [Fanuc's videos of somewhat-autonomous robots](https://youtu.be/7lI-PY7InV8), convert to text, add stuff to the text such as "Plus produces X", the CNS would produce videos that show Fanuc's robots produce for us. Or you could use [videos of how to mass produce robots](https://youtu.be/hLDbRm-98cs), have the CNS convert thus to text, and add to the text such as "Next, instead of standalone robot arms, produces robots with 2 arms + 2 legs" and the CNS would produce videos of how to mass produce this.

How to process this more fast:
[Howto: process devices (phones, laptops, desktops) more fast, lag less](https://swudususuwu.substack.com/p/howto-run-devices-phones-laptops)

Previous posts of artificial CNS series:
[Program general purpose robots as autonomous tools through calculus. Possible to produce general purpose robos as autonomous tools, + close-to-human consciousness](https://swudususuwu.substack.com/p/program-general-purpose-robots-autonomous)
[Albatross performs lots of neural processes per neural volume versus humans, howto base artificial neural networks off of albatross](https://swudususuwu.substack.com/p/albatross-performs-lots-of-neural)
[Destructive (unreversible) upload of human's consciousness](https://swudususuwu.substack.com/p/destructive-unreversible-upload-of)
[Virus analysis tools should use functional analysis + sandboxes + artificial CNS (central nervous systems)](https://swudususuwu.substack.com/p/howto-produce-better-virus-scanners)
[Want this physical form gone so won’t be forced to do "E" with everyone else from now on; am jealous of robots](https://swudususuwu.substack.com/p/want-this-physical-form-gone-so-wont)
