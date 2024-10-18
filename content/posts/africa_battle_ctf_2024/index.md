---
author: pl4int3xt
layout: post
title: Africa battleCTF 2024
date: '2024-10-18'
description: "Only the sharpest minds will make the cut. Eight will qualify, but only one will emerge victorious."
cover: featured.png 
useRelativeCover: true
categories: [Capture The Flag]
---

## Forensics
### Symphony
> Analyze the file. Extensive manipulation is required to uncover what’s hidden within.

RIFF Header (12 bytes):
        52 49 46 46 - "RIFF" in ASCII
        The next 4 bytes (6C 26 05 00) represent the file size in little-endian format. This translates to 340332 bytes in decimal.
        The next 4 bytes (10 00 00 00) are the format identifier (e.g., WAVE, AVI, etc.). This is usually a recognized format like WAVE for audio.

Chunks:
        Each chunk in a RIFF file has an identifier (e.g., fmt , data), chunk size, and data.
        In your case, we can see the data chunk starting at offset 0x20 (64 61 74 61 = data in ASCII), followed by a chunk size of 0x00052648 (the size of the data chunk).

Hex Repair Plan:

    The RIFF header is valid (52 49 46 46).
    The file size in little-endian is correct (6C 26 05 00 = 340332 bytes).
    The fmt chunk is missing. A proper RIFF file (such as a WAV file) needs a format chunk to describe the audio encoding format.

We'll manually insert the fmt chunk before the data chunk. For simplicity, we'll assume a PCM (Pulse-Code Modulation) format,

```bash
Offset 0x0C: 'fmt ' (66 6D 74 20)
Offset 0x10: Subchunk size (0x10 for PCM, meaning 16 bytes for the format chunk)
Offset 0x14: Audio format (0x01 for PCM)
Offset 0x16: Number of channels (0x01 for mono or 0x02 for stereo)
Offset 0x18: Sample rate (e.g., 0x1F40 = 8000 Hz)
Offset 0x1C: Byte rate (SampleRate * NumChannels * BitsPerSample/8)
Offset 0x20: Block align (NumChannels * BitsPerSample/8)
Offset 0x22: Bits per sample (e.g., 8 or 16)
```

```bash
52 49 46 46 6C 26 05 00 57 41 56 45   ; "RIFF" + file size + "WAVE"
66 6D 74 20 10 00 00 00 01 00 01 00   ; 'fmt ' chunk + size + audio format
40 1F 00 00 80 3E 00 00 01 00 08 00   ; Sample rate + byte rate + block align + bits/sample
64 61 74 61 48 26 05 00               ; 'data' chunk identifier + data size
```

From
```bash
52 49 46 46 6C 26 05 00 10 00 00 00 01 00 01 00 40 1F 00 00 40 1F 00 00 01 00 08 00 64 61 74 61
```

To
```bash
52 49 46 46 6C 26 05 00 57 41 56 45 66 6D 74 20 10 00 00 00 01 00 01 00 40 1F 00 00 80 3E 00 00 01 00 08 00 64 61 74 61
```

```python
def hex_to_wav(input_file, output_file):
    try:
        # Read hex data from the input file
        with open(input_file, 'r') as file:
            hex_data = file.read().replace(' ', '').replace('\n', '')
        
        # Convert hex to binary
        binary_data = bytes.fromhex(hex_data)
        
        # Write binary data to the output wav file
        with open(output_file, 'wb') as wav_file:
            wav_file.write(binary_data)
        
        print(f"Successfully created WAV file: {output_file}")
    except Exception as e:
        print(f"Error: {e}")

input_file = 'note.txt'
output_file = 'output.wav'
hex_to_wav(input_file, output_file)
```

![img-description](1.png)
![img-description](2.png)