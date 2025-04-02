---
title: Lesson 11
tags:
  - cs6250
  - streaming
  - bit
  - rate
  - quality
  - service
---

- Compare the bit rate for video, photos, and audio.

  - Videos have the highest bit rate, with photos being the second and audio
    being last.

- What are the characteristics of streaming stored video?

  - Stored video is streamed, interactive, and has continuous playout.

- What are the characteristics of streaming live audio and video?

  - Similar to streaming stored, however, many simultaneous users are
    requesting the video. Live audio or video is also delay-sensitive.

- What are the characteristics of conversational voice and video over IP?

  - Real-time and delay-sensitive, also loss-tolerant

- How does the encoding of analog audio work (in simple terms)?

  - Quantization, the rough conversion of continuous waves to discrete waves

- What are the three major categories of VoIP encoding schemes?

  1. Narrowband
  2. Broadband
  3. Multimode

- What are the functions that signaling protocols are responsible for?

  1. User location
  2. Session establishment
  3. Session negotiation
  4. Call participation management

- What are three QoS VoIP metrics?

  1. end-to-end delay
  2. jitter
  3. packet loss

- What kind of delays are including in “end-to-end delay”?

  - Total delay from mouth to ear. This includes:
    - The time it takes to encode the audio
    - The time it takes to put it in packets
    - All the normal sources of network delay that network traffic encounters
      such as queueing delays
    - Playback delay which comes from the receiver's playback buffer
    - Decoding delay which is the time it takes to reconstruct the signal

- How does “delay jitter” occur?

  - Buffer sizes, queuing delays, network congestion, etc.

- What are the mitigation techniques for delay jitter?

  - Maintaining a buffer called the "jitter buffer" or the "play-out-buffer".
    This mechanism smooths out or hides the variation in delay between
    different received packets, buffering them and playing them out for
    decoding at a steady rate.

- Compare the three major methods for dealing with packet loss in VoIP
  protocols.

  1. Forward Error Concealment (FEC) - transmitting redundant data alongside
     the main transmission, allows the receiver to replace lost data with the
     redundant data.
  2. Interleaving - Mixing chunks of audio together so that if one set of
     chunks is lost, the lost chunks aren't consecutive.
  3. Error concealment - basically guessing what the lost audio packet might
     be.

- How does FEC (Forward Error Correction) deal with the packet loss in VoIP?
  What are the tradeoffs of FEC?

  - Answered above. The more redundant data transmitted, the more bandwidth is
    consumed.

- How does interleaving deal with the packet loss in VoIP/streaming stored
  audio? What are the tradeoffs of interleaving?

  - The receiving side has to wait longer to receive consecutive chunks of
    audio , increasing latency.

- How does error concealment technique deal with the packet loss in VoIP?

  - Answered above.

- What developments lead to the popularity of consuming media content over the
  Internet?

  - Bandwidth for the core network and last-mile access links have increased
    over the years.
  - Compression technologies have become more efficient.

- Provide a high-level overview of adaptive video streaming.
- Which protocol is preferred for video content delivery - UDP or TCP? Why?

  - TCP provides reliability, congestion control.

- What was the original vision of the application-level protocol for video
  content delivery and why was HTTP chosen eventually?

  - Allows the server to be stateless and the intelligence to download the
    video is left to the client. Allows content provides to use the already
    existing CDN. Bypasses middleboxes and firewalls because HTTP is
    well-known.

- Summarize how progressive download works.

  - The client sends byte-range requests for part of the video, instead of
    requesting the entire video. The client pre-fetches some video and stores
    it in the playout buffer.

- How to handle network and user device diversity?

  - Using bitrate adaptation - avoids using one static bitrate. Allows clients
    to determine the bitrate and then increase / decrease based upon network
    conditions.

- How does the bitrate adaptation work in DASH?

  - Dynamic Streaming over HTTP (DASH) just uses dynamic bitrate adaptation.
    Videos are divided into chunks and encoded at multiple bit rates. The
    client adapts the quality video / bitrate it's requesting from the server
    based upon network conditions.

- What are the goals of bitrate adaptation?

  1. Low or zero re-buffering
  2. High video quality
  3. Low video quality variations
  4. Low startup latency

- What are the different signals that can serve as an input to a bitrate
  adaptation algorithm?

  - Network throughput
  - Video buffer

- Explain buffer-filling rate and buffer-depletion rate calculation.

  - The network bandwidth divided by the chunk bitrate is the buffer-filling
    rate.
  - The buffer-depletion rate or the output rate is simply 1 (1 second). How
    fast can we watch video.

- What steps does a simple rate-based adaptation algorithm perform?

  - Estimation of future bandwidth
  - Quantization is the continuous throughput mapped to a discrete bitrate

- Explain the problem of bandwidth over-estimation with rate-based adaptation.

  - Client requests high quality video, however, the bandwidth has dropped
    tremendously - causes the video buffer to deplete. The player takes time to
    converge to the correct bandwidth.

- Explain the problem of bandwidth under-estimation with rate-based adaptation.

  - Under-estimation can cause the network bandwidth to be monopolized by a
    greedier client.
