# CTO (Call Tree Overviewer)

CTO (Call Tree Overviewer) is an IDA plugin for creating a simple and efficiant function call tree graph. It can also summarize function information such as internal function calls, API calls, static linked library function calls, unresolved indirect function calls, string references, structure member accesses, specific comments.

CTO has another helper plugin named "CTO Function Lister", although it can work as a standalone tool. You can think this is an enhanced version of functions window. It lists functions with summarized important information, which is the same as the CTO's one. You can use a regex filter to find nodes with a specific pattern as well.

![CTO-logo](/logo/CTO-Logo-Body.png)
[![Introducing CTO](https://img.youtube.com/vi/zVCpb82UfFs/maxresdefault.jpg)](https://youtu.be/zVCpb82UfFs)

An introduction video is here.  
https://youtu.be/zVCpb82UfFs

You can also check the presentation at VB2021 localhost.  
https://vblocalhost.com/conference/presentations/cto-call-tree-overviewer-yet-another-function-call-tree-viewer/

Submitted paper  
https://vblocalhost.com/uploads/VB2021-Suzuki.pdf

Presentation slides  
https://vblocalhost.com/uploads/2021/09/VB2021-14.pdf

## Requirements
- IDA Pro 7.4 or later (I tested on 7.5 SP3 to 7.7 and 8.2 SP1)
- Python 3.x (I tested on Python 3.8 to 3.11)

You will need at least IDA Pro 7.4 or later because of the APIs that I use.
And use Python 3.x. It should work on Python 2.7 but I did not test enough and I do not support it because it has already obsoleted and deprecated.

## Optional 3rd Party Software
- ironstrings  
  https://github.com/fireeye/flare-ida/tree/master/python/flare/ironstrings

- findcrypt.py  
  https://github.com/you0708/ida/tree/master/idapython_tools/findcrypt

- findguid.py  
  https://github.com/you0708/ida/tree/master/idapython_tools/findguid

- IDA_Signsrch  
  https://sourceforge.net/projects/idasignsrch/

- SusanRTTI  
  https://github.com/nccgroup/SusanRTTI

- Class Informer
  https://sourceforge.net/projects/classinformer/
  https://github.com/herosi/classinformer-ida8

## How to Install
See "[INSTALL](/INSTALL)" file.

## How to Use
To start CTO, press Alt+Shift+C.


Double-click "..." symbol if you want to expand the path.
If you want to create a graph based on a different target function, jump to the target function, click the CTO window, and press "F" key.
See the help by pressing "H" key on the CTO window.

To start CTO Function Lister, press Alt+Shift+F. See the help by pressing "H" key on the CTO Function Lister window as well.

## Note
CTO is still under development and it is unstable yet. I might change the data structure drastically.
CTO accesses sensitive internal data structure of IDA such as low level APIs and PyQt5. And it might cause a crash of IDA.
Do not use this in important situations. I don't take responsibility for any damage or any loss caused by the use of this.

I'm not a programmer. I'm a malware analyst. Please do not expect product-level code.

PRs are welcome. Just complaining and a bug report without enough information are NOT welcome ;-)

## Known Issues
- CTO Function Lister will crash on IDA on Linux for some reasons while it works on Windows. But I can't fix it because I don't have that.
```
QSortFilterProxyModel: index from wrong model passed to mapToSource
```
- Currently, CTO focuses on Intel x64/x86 architecture. If you want to extend other architectures, please send the PR to me.
- On IDA 7.6 including SP1, you will not be able to use ESC for looking backward location history on CTO’s window because of a bug of IDA. Instead, it will close the CTO window if you press it. I reported the bug and it was fixed internally but not released yet. If you want to use it, you will need a fixed ida*.exe binary. Ask hex-rays support. Please do not ask me.
