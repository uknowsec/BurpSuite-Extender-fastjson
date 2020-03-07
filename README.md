# BurpSuite-Extender-fastjson

在原作者的基础改了一个bp自动检测fastjson rce的py插件，可检测1.2.24和1.2.47。若存在漏洞自动标注该流量，并在output中输出内容。 python脚本自行修改ceye和token值。

![](https://github.com/uknowsec/BurpSuite-Extender-fastjson/blob/master/3.jpg)

![](https://github.com/uknowsec/BurpSuite-Extender-fastjson/blob/master/2.jpg)

Reference：https://www.w2n1ck.com/article/44/
