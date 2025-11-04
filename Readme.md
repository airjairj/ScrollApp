# ScrollApp — PC Server

Lightweight Windows server that accepts simple TCP commands (from the phone app) and injects mouse wheel events on the PC.

## Summary
I just wanted to scroll long documents while keeping a bad posture

## What changes between the C and Python version?
Nothing, an EXE is already compiled and ready, but the code is there in case u want to edit something.

## Notes
- The C server uses Windows-specific APIs (Winsock2 and mouse_event) and therefore is Windows-only.
- The secure version of this is a WIP.
- I'm planning to add a version with UDP to connect more phone to the same screen (because why not).

## License
This project is released under the MIT License — see the included LICENSE file for full terms.

You are free to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the software, provided that the original copyright notice and this permission notice are included in all copies or substantial portions of the Software.