# ProtectectionEx
The Kernel Mode Can't Use<br />
Simple Ways such as ZwTerminateProcess<br />
To Terminate Process which Protected By this Driver!<br />
This Driver uses<br />
1.APC (KTHREAD+144) Change{<br />
1111 1111 
1111 1111
1111 1111
1111 1111
1111 1011
1111 1111
1111
}<br />
2.Token Level Up<br />
3.PPL Protection ( Some SourceCode Forked in PPLKILLER(github) )<br />
4.ObCallbacks (Process Callback And Thread CallBack)<br />
We Don't Use UnLink Process or Thread in Some ListEntrys<br />
Because Our Purpose Is To Protect the Process Not Hide<br />
