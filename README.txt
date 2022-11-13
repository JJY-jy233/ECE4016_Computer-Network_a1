README：
	2 versions for simulating DNS server
	probably 1.1 will be more efficient

	To execute the program, use "python DNS1.1.py", then it will ask you to enter a fiag to determine which method will the program use
if the fiag is 0:
	it will ask the public server and get the answer.
When flag is 1:
	it will do iterative query by asking the root, then based on the answer
	provided by root, ask next authority DNS, and print the ip address it passed, after getting the answer, store it into the cache in case if further identical query occurs.
	After preparing answer,pack it into bytes, and send it to client.

How to send query to this simulated DNS server:
	1. use "cmd" or "powershell" commend to enter the command line interface or shell interface
	2. use "dig <website> @127.0.0.1 -p1234" to send query to DNS server, replace <website> with any website you want eg."www.baidu.com"

Note: The query type can only be IN and CNAME and NS other type like MX will lead program collapse
