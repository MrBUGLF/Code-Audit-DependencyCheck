# Code-Audit-DependencyCheck

## 简介
- 代码安全组件扫描-DependencyCheck升级版，增加对maven项目pom.xml文件引用的依赖jar进行组件漏洞扫描并输出报告
- DependencyCheck官方README：[README-DependencyCheck.md](./README-DependencyCheck.md)

## 编译环境

- [x] java :  `java -version` 1.8
- [x] maven :  `mvn -version` >= 3.5.0

## 调试

1. 用VS Code打开文件夹```Code-Audit-DependencyCheck```
2. 等待```JAVA PROJECTS面板```加载完毕后，然后```组合键Ctrl+F5```
3. 选择主类: ```org.owasp.dependencycheck.App```

## 编译与发布

1. 进入项目根目录下，执行编译命令：```mvn -s settings.xml clean install -DskipTests=true```

   ![image-20221009145318829](./README.assets/image-20221009145318829.png)

   

2. 初始编译完成后发布的版本不含漏洞库：```Code-Audit-DependencyCheck\cli\target\dependency-check-7.2.1-release.zip```

![image-20221009145417199](./README.assets/image-20221009145417199.png)

3. 若需要包含最新漏洞库的版本：执行更新库命令```Code-Audit-DependencyCheck\cli\target\release\bin\dependency-check.bat --updateonly```

   下载好的漏洞库文件在`Code-Audit-DependencyCheck\cli\target\release\data\nvdcache`目录下

   ![image-20221009145621657](./README.assets/image-20221009145621657.png)

   

4. 然后打包```Code-Audit-DependencyCheck\cli\target\release```生成新的```dependency-check-7.2.1-release.zip```



## 使用方式

1. 使用下载好的漏洞库进行扫描，为防止误报过多，不扫描JS和NodeJS

`dependency-check.bat --project [项目名称] -s [扫描目录] -o [报告输出目录] --format [报告输出格式HTML/CSV等] --cveUrlModified nvdcve-1.1-modified.json.gz<本地nvd库的url> --cveUrlBase nvdcve-1.1-2022.json.gz<本地nvd库的url> --disableRetireJS --disableNodeJS -n[表示不更新漏洞库]`

2. 扫描前先更新漏洞库

`dependency-check.bat --project [项目名称] -s [扫描目录] -o [报告输出目录] --format [报告输出格式HTML/CSV等]  --disableRetireJS --disableNodeJS`

## 改动文件
```
core\src\main\java\org\owasp\dependencycheck\analyzer\JarAnalyzer.java
core\src\main\java\org\owasp\dependencycheck\xml\pom\PomParser.java增加parsePomXML方法
core\src\main\java\org\owasp\dependencycheck\xml\pom\PomUtils.java增加readPomXML方法
core\pom.xml添加maven-model组件
编译后的dependency-check\lib目录下添加maven-model.jar和plexus-utils.jar文件
```
## 优化项
- [x] 增加maven pom.xml文件中依赖漏洞扫描

- [x] 优化输出html报告中锚点定位问题

- [ ] 下载maven cve库和最新版本到本地进行离线更新