# 修改运动步数 (微信，支付宝)
通过青龙面板 使用 **Zepp Life** app（*原**小米运动**app*）修改微信步数和支付宝步数，Github Action 可设置每日定时执行。
> 2025.3.8测试成功:ghost:

[![修改微信步数](https://github.com/Caryio/ZeppLifeChangeWechatSport/actions/workflows/RunFunction.yml/badge.svg?branch=main)](https://github.com/Caryio/ZeppLifeChangeWechatSport/actions/workflows/RunFunction.yml)
## 目录
* [准备工作](#准备工作)
* [使用指南](#使用指南)
  * [通过青龙面板](#通过青龙面板)
* [注意事项](#注意事项)
* [更新日志](#更新日志)
* [声明](#声明)

## 准备工作
使用本仓库需要 Zepp Life app（*原小米运动app*），请务必把 Zepp Life 注册好，设置好，与微信的同步/第三方接入什么的都弄好再往下看

<p align="right">（<a href="#修改微信运动步数">回到顶部</a>）</p>
  
## 使用指南
### 通过青龙面板
下载`shuabu.py`文件
**青龙面板添加环境变量**
   <table>
    <tr>
     <td colspan="1">环境变量</td>
     <td colspan="1">数值</td>
    </tr>
    <tr>
     <td>zepp_user</td>
     <td>zeppp_assword</td>
    </tr>
    <tr>
     <td>18899996666</td>
     <td>密码</td>
    </tr>
   </table>
   
   （`zepp_user`是注册Zepp Life app的手机号，`zeppp_assword`是账号密码。
   每次运行的步数已随机且根据时间判断刷步大小，如需修改自行改如下代码
```
if at22 < 2400:
    if at22 > int(2350):
        step=str(randint(25798, 36723))
    elif at22 > int(2326):
        step = str(randint(15339,19779))
    elif at22 > int(2240):
        step = str(randint(9307,12789))  
    elif at22 > int(2206):
        step = int(randint(7680,9024)) 
    elif at22 > int(1920):
        step = int(randint(6145,8024)) 
    elif at22 > int(1510):
        step = int(randint(4097,6597)) 
    elif at22 > int(1205):
        step = int(randint(2528,4833)) 
    elif at22 > int(1010):
        step = int(randint(1528,3133)) 
    elif at22 > int(801):
        step = int(randint(507,1289)) 
    else:
        step = int(randint(307,589))
else:
    step = int(randint(107,300))
```
   

<p align="right">（<a href="#修改微信运动步数">回到顶部</a>）</p>
  

自行修改定时规则，如 12 11 13 * * *
即可每日在北京时间13:11:12	运行。
这是我的，在每天7点，12点，19点，22点，23点的56分11秒运行,既降低对每日排行榜的影响，也保证第二天支付宝最大数值的森林能量
```
11 56 7,12,19,22,23 * * *
```
  
<p align="right">（<a href="#修改微信运动步数">回到顶部</a>）</p>
  
## 注意事项
* 不保证一定成功，调用接口每日有限制量，可能会黑号:
  
## 更新日志
  - **`v0.1`** 2025.2.8：上传做备份

## 声明
- 本项目仅供编程学习/测试使用
- 根据 [Caryio/ChangeWechatSport](https://github.com/Caryio/ChangeWechatSport/tree/main) 修改
- 请在国家法律法规和校方/公司相关原则下使用
- 开发者不对任何下载者和使用者的任何行为负责

<p align="right">（<a href="#修改微信运动步数">回到顶部</a>）</p>
