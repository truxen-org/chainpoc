This project is a proof of concept on the Trusted Computing enhanced blockchain. This code base is derived from the combination of Ethereum eth-go-0.3.1 and go-ethereum-0.2.2, the bootstrap package. 



Usage
====================

``` 
>go build
>./chainpoc
```

Command line options
====================

```
-i                              Show PCR info.
-c=<full path of config file>   Specify config.
```

Developer console commands
==========================

```
addp <host>:<port>     Connect to the given host
cp                     Propose local node into network
tx <addr> <amount>     Send <amount> Wei to the specified <addr>
``` 


Performance test
==========================

```
set "StartMining" to false in config.json.
ubuntu@chainpc:~/go/src/dp2u.com/chainpoc$ ./chainpoc
...
>>>
>>> ca 50000
2018/11/23 17:52:24 creating 50000 accounts ...
2018/11/23 17:52:34 //////////create accounts done.
>>> b 50000
2018/11/23 17:52:40 trying tx test of 50000 accounts ...
>>>>>>>>>>>>>>>>>>QueueTransactions  20.696280449s
>>> m
2018/11/23 17:53:41 Starting miner...
>>> 2018/11/23 17:53:41 ++++++++++++++++++++++Create a new block ...
``` 


