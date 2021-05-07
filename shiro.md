# Shiro框架在项目中的应用

# Shiro 框架简介

## Shiro 概述

Shiro 是Apache公司推出一个权限管理框架,其内部封装了项目中认证，授权，加密，会话等逻辑操作，通过Shiro框架可以简化我们项目权限控制逻辑的代码的编写。其认证和授权业务分析，如图所示：

![image-20210115171115724](D:\TCGBIII\DEVDOCS\Day18\shiro.assets\image-20210115171115724.png)

## Shiro 框架概要架构

Shiro 框架中主要通过Subject,SecurityManager,Realm对象完整认证和授权业务，其简要架构如下：

![image-20210115164900666](D:\TCGBIII\DEVDOCS\Day18\shiro.assets\image-20210115164900666.png)

其中：

* Subject 此对象负责提交用户身份、权限等信息

* SecurityManager 负责完成认证、授权等核心业务

* Realm 负责通过数据逻辑对象获取数据库或文件中的数据。

  

## Shiro 框架详细架构分析

Shiro 框架进行权限管理时,要涉及到的一些核心对象,主要包括:认证管理对象,授权管理对象,会话管理对象,缓存管理对象,加密管理对象以及 Realm 管理对象(领域对象:负责处理认证和授权领域的数据访问题)等，其具体架构如图- 所示：

![image-20210115165757540](D:\TCGBIII\DEVDOCS\Day18\shiro.assets\image-20210115165757540.png)

其中：

1) Subject（主体）:与软件交互的一个特定的实体（用户、第三方服务等）。

2) SecurityManager(安全管理器) :Shiro 的核心，用来协调管理组件工作。

3) Authenticator(认证管理器):负责执行认证操作。

4) Authorizer(授权管理器):负责授权检测。

5) SessionManager(会话管理):负责创建并管理用户 Session 生命周期，提供一

个强有力的 Session 体验。

6) SessionDAO:代表 SessionManager 执行 Session 持久（CRUD）动作，它允

许任何存储的数据挂接到 session 管理基础上。

7) CacheManager（缓存管理器）:提供创建缓存实例和管理缓存生命周期的功能。

8) Cryptography(加密管理器):提供了加密方式的设计及管理。

9) Realms(领域对象):是 shiro 和你的应用程序安全数据之间的桥梁。



# Shiro 框架基础配置



## Shiro 依赖

在项目中添加Shiro相关依赖(参考官网http://shiro.apache.org/spring-boot.html),假如项目中添加过shiro-spring依赖，将shiro-spring依赖替换掉即可。

```
<dependency>
    <groupId>org.apache.shiro</groupId>
    <artifactId>shiro-spring-boot-web-starter</artifactId>
    <version>1.7.0</version>
</dependency>
```

说明，添加完此依赖，直接启动项目会启动失败，还需要额外的配置。

## Shiro 基本配置

**第一步：创建一个Realm类型的实现类(基于此类通过DAO访问数据库)，关键代码如下：**

```
package com.cy.pj.sys.service.realm;
public class ShiroRealm extends AuthorizingRealm {
    /**此方法负责获取并封装授权信息*/
    @Override
    protected AuthorizationInfo doGetAuthorizationInfo(
             PrincipalCollection principalCollection) {
        return null;
    }
    /**此方法负责获取并封装认证信息*/
    @Override
    protected AuthenticationInfo doGetAuthenticationInfo(
         AuthenticationToken authenticationToken) throws AuthenticationException {
        return null;
    }
}
```

**第二步：在项目启动类中添加Realm对象配置，关键代码如下：**

```
@Bean
public Realm realm(){//org.apache.shiro.realm.Realm
 return new ShiroRealm();
}
```

**第三步：在启动类中定义过滤规则(哪些访问路径要进行认证才可以访问),关键代码如下：**

```
    @Bean
    public ShiroFilterChainDefinition shiroFilterChainDefinition() {
        DefaultShiroFilterChainDefinition chainDefinition = 
               new DefaultShiroFilterChainDefinition();
        LinkedHashMap<String,String> map=new LinkedHashMap<>();
        //设置允许匿名访问的资源路径(不需要登录即可访问)
        map.put("/bower_components/**","anon");//anon对应shiro中的一个匿名过滤器
        map.put("/build/**","anon");
        map.put("/dist/**","anon");
        map.put("/plugins/**","anon");
        //设置需认证以后才可以访问的资源(注意这里的顺序,匿名访问资源放在上面)
        map.put("/**","authc");//authc 对应一个认证过滤器，表示认证以后才可以访问
        chainDefinition.addPathDefinitions(map);
        return chainDefinition;
    }
```

**第四步：配置认证页面(登录页面)**

在spring的配置文件(application.yml)中，添加登录页面的配置，关键代码如下：

```
shiro:
   loginUrl: /login.html
```

其中，login.html页面为项目中static目录定义好的一个页面。

**第五步：启动服务进行访问测试**

打开浏览器，输入http://localhost/doIndexUI检测是否会出现登录窗口，如图所示：

![image-20210116090019209](D:\TCGBIII\DEVDOCS\Day18\shiro.assets\image-20210116090019209.png)



# Shiro认证业务分析及实现

## 认证流程分析

当我们在登录页面，输入用户信息，提交到服务端进行认证，其中shiro框架的认证时序如图所示：

![image-20210116090848141](D:\TCGBIII\DEVDOCS\Day18\shiro.assets\image-20210116090848141.png)

其中：

1) token ：封装用户提交的认证信息（例如用户名和密码）的一个对象。

2) Subject: 负责将认证信息提交给SecurityManager对象的一个主体对象。

3) SecurityManager是shiro框架的核心，负责完成其认证、授权等业务。

4) Authenticator 认证管理器对象，SecurityManager继承了此接口。

5) Realm 负责从数据库获取认证信息并交给认证管理器。

## Shiro框架认证业务实现

**第一步：在SysUserDao中定义基于用户名查询用户信息的方法，关键代码如下：**

```
@Select("select * from sys_users where username=#{username}")
SysUser findUserByUsername(String username);
```

**第二步:修改ShiroRealm中获取认证信息的方法，关键代码如下：**

```java
 @Autowired
 private SysUserDao sysUserDao;
 @Override
 protected AuthenticationInfo doGetAuthenticationInfo(
            AuthenticationToken authenticationToken) throws AuthenticationException {
         //1.获取用户提交的认证用户信息
        UsernamePasswordToken upToken=(UsernamePasswordToken) authenticationToken;
        String username=upToken.getUsername();
         //2.基于用户名查询从数据库用户信息
        SysUser sysUser = sysUserDao.findUserByUsername(username);
        //3.判断用户是否存在
        if(sysUser==null) throw new UnknownAccountException();//账户不存在
         //4.判断用户是否被禁用
        if(sysUser.getValid()==0)throw new LockedAccountException();
         //5.封装认证信息并返回
        ByteSource credentialsSalt=
                ByteSource.Util.bytes(sysUser.getSalt());
         SimpleAuthenticationInfo info=
                new SimpleAuthenticationInfo(
                        sysUser, //principal 传入的用户身份
                        sysUser.getPassword(),//hashedCredentials
                        credentialsSalt,//credentialsSalt
                        getName());
        return info;//返回给认证管理器
    }
```

**第三步:在ShiroRealm中重谢获取凭证加密算法的方法，关键代码如下：**

```java
   @Override
    public CredentialsMatcher getCredentialsMatcher() {
        HashedCredentialsMatcher matcher=new HashedCredentialsMatcher();
        matcher.setHashAlgorithmName("MD5");//加密算法 
        matcher.setHashIterations(1);//加密次数
        return matcher;
    }
```

**第四步：在SysUserController中添加处理登录请求的方法,关键代码如下:**

```java
@RequestMapping("doLogin")
public JsonResult doLogin(String username,String password){
   UsernamePasswordToken token = new UsernamePasswordToken(username, password);
   Subject currentUser = SecurityUtils.getSubject(); 
   currentUser.login(token);
   return new JsonResult("login ok");
}
```

**第五步:统一异常处理类中添加shiro异常处理代码，关键如下：**

```java
 @ExceptionHandler(ShiroException.class)
 public JsonResult doShiroException(ShiroException e){
       JsonResult r=new JsonResult();
       r.setState(0);
       if(e instanceof UnknownAccountException){
           r.setMessage("用户名不存在");
       }else if(e instanceof IncorrectCredentialsException){
           r.setMessage("密码不正确");
       }else if(e instanceof LockedAccountException){
           r.setMessage("账户被锁定");
       }else if(e instanceof AuthorizationException){
           r.setMessage("没有权限");
       }else{
           r.setMessage("认证或授权失败");
       }
       return r;
    }
```



**第五步：在过滤配置中允许登录时的url匿名访问，关键代码如下：**

```java
...
map.put("/user/doLogin","anon");
...
```

**第六步:再过滤配置中配置登出url操作，关键代码如下:**

```java
..
map.put("/doLogout","logout");//logout是shiro框架给出一个登出过滤器
...
```

**第六步：启动服务器，进行登录访问测试**

![image-20210116105840608](D:\TCGBIII\DEVDOCS\Day18\shiro.assets\image-20210116105840608.png)



**第七步：Shiro框架认证流程总结分析**

* Step01：登录客户端(login.html)中的用户输入的登录信息提交SysUserController对象

* Step02：SysUserController对象基于doLogin方法处理登录请求.

* Step03：SysUserController中的doLogin方法将用户信息封装token中， 然后基于subject对象将token提交给SecurityManager对象。

* Step04：SecurityManager对象调用认证方法(authenticate)去完成认证，在此方法内部会调用ShiroRealm中的doGetAuthenticationInfo获取数据库中的用户信息，然后再与客户端提交的token中的信息进行比对，比对时会调用getCredentialsMatcher方法获取凭证加密对象，通过此对象对用户提交的token中的密码进行加密。

# Shiro授权业务分析及实现

## 业务分析

已认证用户，在进行系统资源的访问时，我们还要检查用户是否有这个资源的访问权限。并不是所有认证用户都可以访问系统内所有资源，也应该是受限访问的。

## Shiro框架中的授权实现

**第一步: 在SysMenuDao中定义查询用户权限标识的方法,关键代码分析:**

```
Set<String> findUserPermissions(Integer userId);
```

**第二步:在SysMenuMapper中添加查询用户权限标识的SQL映射,关键代码如下:**

```
<select id="findUserPermissions" resultType="string">
 select distinct permission
 from sys_user_roles ur join sys_role_menus rm join sys_menus m
 on ur.role_id=rm.role_id and rm.menu_id=m.id
 where ur.user_id=#{userId} and m.permission is not null and  trim(m.permission)!='' 
</select>
```

**第三步:修改ShiroRealm中获取权限并封装权限信息的方法,关键代码如下**

```java
    @Override
    protected AuthorizationInfo doGetAuthorizationInfo(
            PrincipalCollection principalCollection) {
        //1.获取登录用户(登录时传入的用户身份是谁)
        SysUser user= (SysUser) principalCollection.getPrimaryPrincipal();
        //2.基于登录用户id获取用户权限标识
        Set<String> stringPermissions=
        sysMenuDao.findUserPermissions(user.getId());
        //3.封装数据并返回
        SimpleAuthorizationInfo info=new SimpleAuthorizationInfo();
        info.setStringPermissions(stringPermissions);
        return info;//返回给授权管理器
    }
```

**第四步:定义授权切入点方法,示例代码如下:**

在shiro框架中,授权切入点方法需要通过@RequiresPermissions注解进行描述,例如:

```java

    @RequiresPermissions("sys:user:update")
    public int validById(Integer id,Integer valid){
        int rows=sysUserDao.validById(id,valid);
        if(rows==0)throw new ServiceException("记录可能已经不存在");
        return rows;
    }
    
```

其中, @RequiresPermissions注解中定义的内容为,访问此方法需要的权限.

**第五步:启动服务进行访问测试**

在访问时首先要检测一下用户有什么权限,检测过程,先查询用户有什么角色,再查看角色有什么菜单的访问权限.