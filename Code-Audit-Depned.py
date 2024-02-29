# -*- coding: utf-8 -*-

import stat
import traceback
import os
import datetime
import chardet
import gitlab
import pandas as pd
from git.repo import Repo
import shutil
import functools
import argparse
import requests
import yaml
import zipfile
import re
from bs4 import BeautifulSoup
from jinja2 import Environment, FileSystemLoader, select_autoescape
import translators as ts

JDK_VERSION = '8'

def logger(func):
    @functools.wraps(func)
    def wrapper(*args, **kw):
        print('开始执行 %s():' % func.__name__)
        result = func(*args, **kw)
        print('执行完毕 %s():' % func.__name__)
        return result

    return wrapper


def is_google_connected():
    """
    判断当前机器是否可访问谷歌
    """
    try:
        requests.get("http://www.google.com", timeout=3)
    except:
        return False
    return True


def trans(src_text,from_lang = 'auto',to_lang='zh-CN'):
    """
    默认使用bing进行翻译,设置sleep时间防止短期频繁请求导致服务不可用,如果能访问谷歌则用google-translate
    """
    translator = 'google' if is_google_connected() else 'bing'
    return ts.translate_text(src_text ,translator=translator, from_language=from_lang,to_language=to_lang, sleep_seconds=2, limit_of_length = 500000)


def get_DependencyCheck():
    current_dir = os.path.dirname(__file__)
    depend_check_bat = os.path.join(current_dir, 'dependency-check', 'bin', 'dependency-check.bat')
    if not os.path.exists(depend_check_bat):
        for x in os.listdir('dependency-check')[::-1]:
            cadc_zip_m = re.match('Code-Audit-DependencyCheck-(.*?)\.zip', x)
            if cadc_zip_m:
                depend_check_zip = os.path.join(current_dir, 'dependency-check', cadc_zip_m[0])
                print('[+] 正在部署' + depend_check_zip)
                unzip_file(depend_check_zip, 'dependency-check')
                return depend_check_bat
        print(
            '[-] 找不到dependency-check/bin/dependency-check.bat，也找不到dependency-check/Code-Audit-DependencyCheck-***.zip')
    return depend_check_bat


def unzip_file(zip_src, dst_dir):
    r = zipfile.is_zipfile(zip_src)
    if r:
        fz = zipfile.ZipFile(zip_src, 'r')
        for file in fz.namelist():
            fz.extract(file, dst_dir)
    else:
        print('[-] 这不是一个zip文件:' + zip_src)


def pd_excel(filename, sheet_name=None):
    extension = filename.split('.')[-1]
    if extension in ['xls', 'xlsx']:
        excel = pd.read_excel(filename, sheet_name=sheet_name)
        excel = excel.fillna(value="")
    elif extension in ['csv']:
        read_file = open(filename, 'rb').read()
        char_encoding = chardet.detect(read_file)['encoding']
        if char_encoding.startswith('GB'):
            char_encoding = 'GB18030'
        excel = pd.read_csv(filename, encoding=char_encoding)
        excel = excel.fillna(value="")
    else:
        excel = {}
    return excel


def read_config(file):
    """
    读取yml配置文件内容
    return
    git项目地址和分支
    本地项目路径
    gitlab库地址
    """
    try:
        with open(file, encoding='utf-8') as f:
            yml_config = yaml.safe_load(f)
            gitlab_projects = yml_config['gitlab_projects']
            local_dirs = yml_config['local_dirs']
            gitlab_libs = yml_config['gitlab_libs']
            scan_js = yml_config['is_scan_js']

        return gitlab_projects, local_dirs, gitlab_libs, scan_js
    except:
        print("配置文件config.yml不存在", traceback.print_exc())


def get_gitlab_projects(gitlab_url, gitlab_private_token):
    """
    输入:gitlab库地址和token
    return: 所有库内系统名列表/url列表/默认分支列表
    """
    try:
        gl = gitlab.Gitlab(gitlab_url, private_token=gitlab_private_token)
        projects = gl.projects.list(all=True)
        return projects
    except:
        print("获取gitlab库项目信息失败")





@logger
def get_gitlab_project_codes(project_url, ref='master'):
    try:
        # 创建本地存储地址
        project_name = os.path.basename(project_url).split('.')[0]
        download_path = os.path.join(project_name, ref)
        if os.path.exists(download_path):
            shutil.rmtree(download_path, onerror=remove_readonly_files)
        # 从远程仓库下载代码
        Repo.clone_from(project_url, to_path=download_path, branch=ref)
        # 获取项目所有分支
        repo = Repo(download_path)
        branches = repo.remote().refs
        print(f"{project_name}项目所有的分支:")
        for item in branches:
            print(f"分支:{item.remote_head}")
        print(f'下载{project_url}的{ref}分支完成')
        return project_name, download_path
    except:
        print("读取git项目失败")


def remove_readonly_files(func, path, _):
    os.chmod(path, stat.S_IWRITE)
    func(path)


@logger
def excute_depend_check(project_name='TEST', scan_path='.', scan_js=False):
    """
    执行组件扫描
    :param scan_js:
    :param project_name: 项目名称
    :param scan_path: 扫描路径
    :return: 组件扫描报告文件路径
    """
    try:
        current_dir = os.path.dirname(__file__)
        today = datetime.date.today()
        report_path = os.path.join(current_dir, f'{project_name}_{today}_dependency_check_report.csv')

        depend_check_bat = get_DependencyCheck()
        cveUrlModified = os.path.join(current_dir, 'dependency-check', 'data', 'nvdcache',
                                      'nvdcve-1.1-modified.json.gz')
        cveUrlBase = os.path.join(current_dir, 'dependency-check', 'data', 'nvdcache', 'nvdcve-1.1-2022.json.gz')

        
        print(f'{project_name}项目组件扫描开始执行')
        if not scan_js:
            depend_check_cmd = f'{depend_check_bat} --disableRetireJS --disableNodeJS --disableNodeAudit --disableAssembly --project {project_name} -s {scan_path} -o {report_path} --format CSV '
        else:
            depend_check_cmd = f'{depend_check_bat}  --project {project_name} -s {scan_path} -o {report_path} --format CSV '
        os.system(depend_check_cmd)
        print(f'{project_name}项目组件扫描执行完成')
        return report_path
    except:
        traceback.print_exc()



def get_jar_latest_version(group_id, artifact_id, jdk_version):
    """
    获取jar的最新版本
    :param group_id:
    :param artifact_id:
    :return:
    """
    try:
        # 先判断是否存在已有表里
        data = pd.read_excel('extend-components-sec-version.xlsx')
        sec_version = data.loc[(data['group_id'] == str(group_id)) & (data['artifact_id'] == str(artifact_id)) & (data['Supported_JDK_versions'].str.contains(jdk_version)), ['sec_version']]

        if not sec_version.empty:
            res_sec_version = []
            for row in sec_version.itertuples():
                res_sec_version.append(getattr(row, 'sec_version'))
            return '或'.join(res_sec_version)
        # 这个URL虽然可以查询组件版本,但对于判断组件最新版本比较困难
        # url = "https://search.maven.org/solrsearch/select?q=g:{}+AND+a:{}&core=gav&rows=20&wt=json".format(group_id, artifact_id)
        # 根据groupId和artifactId 查询组件最新版本页面进行解析
        url = 'https://search.maven.org/solrsearch/select?q=g:{}+AND+a:{}&core=gav&rows=1'.format(group_id, artifact_id)
        headerData = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/106.0.0.0 Safari/537.36'
        }
        response = requests.get(url, headers=headerData).json()
        latest_version = response['response']['docs'][0]['v']
        return latest_version
    except Exception as e:
        traceback.print_exc()
        print("error: %s. artifact_id=%s." % (e, artifact_id))


def get_js_latest_version(npm):
    """
    获取js最新版本
    输入参数示例:axios
    """
    try:
        response = requests.get(url="https://registry.npmjs.org/" + npm + "/latest").json()
        version = response["version"]
        return version
    except Exception as e:
        traceback.print_exc()


def get_go_module_latest_version(go_pkg):
    """
    获取go模块最新版本
    输入参数示例:github.com/gin-gonic/gin
    """
    try:
        response = requests.get(url="https://pkg.go.dev/" + go_pkg + "?tab=versions").content
        soup = BeautifulSoup(response, "html.parser")
        version_str = soup.find("a", class_="js-versionLink")
        version = version_str.contents[0]
        return version
    except Exception as e:
        traceback.print_exc()


@logger
def analyze_report(project_name, report_path):
    """
    读取组件扫描报告文件内容输出到word文档
    :param project_name: 项目名称
    :param report_path: 报告文件路径
    :return: word报告文档
    """
    # 漏洞标题 - DependencyName + CVE[有多个则统计总数量]
    # 漏洞URL - DependencyName
    # 缺陷描述 - Vulnerability
    # 风险等级 - 选取CVSSv3_BaseSeverity CRITICAL 和 CVSSv2_Severity HIGH以上
    # 漏洞验证 - Identifiers
    selected_cols = ['DependencyName', 'CVE', 'DependencyPath', 'Vulnerability', 'CVSSv2_Severity', 'CVSSv2_Score',
                     'CVSSv3_BaseSeverity',
                     'Identifiers']
    # 筛选特定需要的列来组成word文档输出内容
    data = pd.read_csv(report_path, usecols=selected_cols)
    # 筛选CVSSv2评分为严重和高危的漏洞组件和CVSSv3评分为严重的
    res_data = data[
        (data['CVSSv2_Severity'].isin(['CRITICAL', 'HIGH'])) | (data['CVSSv3_BaseSeverity'].isin(['CRITICAL']))]
    # 分组循环遍历相同组件的多个CVE漏洞输出

    groups = res_data.groupby('DependencyName')
    vul_depend_index = 1
    # 组件扫描漏洞对象列表
    depend_vuln_list = []
    for name, group in groups:
        # 获取评分最高的漏洞信息进行报告输出
        sorted_group = group.sort_values(by='CVSSv2_Score', ascending=False)
        cve_name = sorted_group.head(1)['CVE'].iloc[0]
        depend_vuln = {}
        # 漏洞描述
        depend_vuln['vuln_desc'] = trans(sorted_group.head(1)['Vulnerability'].iloc[0])
        risk = sorted_group.head(1)['CVSSv2_Severity']
        VULN_URL = []
        DenPath = []
        for vuln in group['DependencyName']:
            VULN_URL.append(vuln)
        for dp in group['DependencyPath']:
            DenPath.append(dp)
        # 漏洞URL
        depend_vuln['vuln_url'] = set(VULN_URL)
        if name.endswith('.jar'):
            dep_name = name.replace(".jar", "")
            title = f'4.{vul_depend_index} 组件{dep_name} 存在{cve_name}漏洞'
        elif 'shaded:' in name:
            dep_name = name[name.index('shaded:') + 7:-1]
            title = f'4.{vul_depend_index} 组件{dep_name} 存在{cve_name}漏洞'
        else:
            dep_name = name
            title = f'4.{vul_depend_index} 组件{dep_name} 存在{cve_name}漏洞'
        # 漏洞标题
        depend_vuln['vuln_title'] = title
        # 漏洞风险等级
        depend_vuln['risk_level'] = '严重' if 'CRITICAL' in risk else '高危'

        vuln_verifys = []
        for index, p in enumerate(set(DenPath)):
            # 显示组件所在项目位置
            d_p = p[p.index(project_name):]
            # 如果存在?号
            json_index = d_p.find('?')
            if json_index > 0:
                d_p = d_p[:json_index]
            if name.endswith('.jar'):
                if 'pom.xml' in d_p:
                    pom_index = d_p.index('pom.xml') + 7
                    vuln_verify = f'{index + 1}.项目中的{d_p[:pom_index]}引用了{name}组件'
                else:
                    vuln_verify = f'{index + 1}.项目引用了{d_p}组件'
            elif 'shaded:' in name:
                in_name = name[name.index('shaded:') + 7:-1]
                vuln_verify = f'{index + 1}.项目中的{d_p}引用了{in_name}组件'
            else:
                in_name = name
                vuln_verify = f'{index + 1}.项目中的{d_p}引用了{in_name}组件'
            vuln_verifys.append(vuln_verify)
        # 漏洞验证
        depend_vuln['vuln_verify'] = vuln_verifys
        identifier = group['Identifiers'].iloc[0]
        if isinstance(identifier, str):
            if 'maven' in identifier:
                group_and_artifact = identifier[identifier.index("/") + 1:identifier.index("@")]
                group_id = group_and_artifact.split("/")[0]
                artifact_id = group_and_artifact.split("/")[1]
                jar_latest_version = get_jar_latest_version(group_id, artifact_id, JDK_VERSION)
                fix_suggestion = f'请升级{dep_name}组件版本至{jar_latest_version}'
            elif 'npm' in identifier or 'javascript' in identifier:
                artifact_id = identifier[identifier.index("/") + 1:identifier.index("@")]
                js_latest_version = get_js_latest_version(artifact_id)
                fix_suggestion = f'请升级{dep_name}组件版本至{js_latest_version}'
            else:
                fix_suggestion = f'请升级{dep_name}组件版本'
        else:
            fix_suggestion = f'请升级{dep_name}组件版本'
        # 修复建议
        depend_vuln['fix_suggestion'] = fix_suggestion
        depend_vuln_list.append(depend_vuln)

        vul_depend_index += 1
    generate_html(project_name, depend_vuln_list)

@logger
def generate_html(project_name, body):
    """
    传入组件扫描漏洞内容根据模板生成html文件
    """

    today = datetime.date.today().strftime("%Y%m%d")
    report_html = f'组件扫描报告-{project_name}-{today}.html'
    if os.path.exists(report_html):
        os.remove(report_html)

    env = Environment(loader=FileSystemLoader('./templates'),autoescape=select_autoescape(enabled_extensions=('html', 'xml'),default_for_string=True,))
    template = env.get_template('template.html')
    with open(report_html, "w",encoding='utf-8') as f:
        html_content = template.render(body=body)
        f.write(html_content)

def google_tanslate(src_text):
    """
    使用https://pypi.org/project/pygoogletranslation/进行谷歌翻译
    pip install pygoogletranslation
    """
    translator = Translator(service_urls=[
      'translate.google.cn',   
    ])
    tanslated_text = translator.translate(src_text, dest='zh-CN')
    return tanslated_text


if __name__ == '__main__':
    description_tips = '''说明:项目组件漏洞扫描
    主要对jar和pom.xml文件里的依赖内容进行漏洞扫描输出报告
    '''
    usage_tips = """Examples:
    1.指定参数输入
    python %(prog)s -p  "git项目地址"
    python %(prog)s -p  "git项目地址" -b "项目分支"
    python %(prog)s -l  "本地git项目路径"
    python %(prog)s -g  "gitlab库地址"
    
    2.所有配置信息写在config.yml中
    # git项目地址和分支
    gitlab_projects: 
    - {project_url: http://xxx.git, project_branch: master}
    - {project_url: http://yyy.git, project_branch: master}
    
    # 本地项目路径
    local_dirs:
    - txcard_server1
    - txcard_server
    
    # gitlab库地址
    gitlab_libs:
    - {gitlab_url: http://xxx:8080,  gitlab_private_token: xxx}
    - {gitlab_url: http://xxx:8081,  gitlab_private_token: yyy}
    
    # 默认不开启JS扫描
    is_scan_js: false

    python %(prog)s 
    """
    parser = argparse.ArgumentParser(description=description_tips, epilog=usage_tips,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('-p', '--project-url', help='git项目地址')
    parser.add_argument('-b', '--branch', default='master', help='git项目分支')
    parser.add_argument('-l', '--local-dir', help='本地git项目路径')
    parser.add_argument('-g', '--gitlab-url', help='gitlab库地址')
    parser.add_argument('-t', '--gitlab-private-token', help='gitlab库token')
    options = parser.parse_args()
    gitlab_projects, local_dirs, gitlab_libs, scan_js= read_config('config.yml')
    if options.project_url:
        project_name, download_path = get_gitlab_project_codes(project_url=options.project_url, ref=options.branch)
        depend_report_path = excute_depend_check(project_name, download_path, scan_js=scan_js)
        word_report = analyze_report(project_name=project_name, report_path=depend_report_path)
    if options.local_dir:
        project_name = os.path.basename(options.local_dir)
        depend_report_path = excute_depend_check(project_name, options.local_dir, scan_js=scan_js)
        word_report = analyze_report(project_name=project_name, report_path=depend_report_path)
    if options.gitlab_url and options.gitlab_private_token:
        projects = get_gitlab_projects(options.gitlab_url, options.gitlab_private_token)
        for project in projects:
            project_url = project.ssh_url_to_repo
            project_branch = project.default_branch
            project_name, download_path = get_gitlab_project_codes(project_url=project_url, ref=project_branch)
            depend_report_path = excute_depend_check(project_name, download_path, scan_js=scan_js)
            word_report = analyze_report(project_name=project_name, report_path=depend_report_path)

    # 如果git项目地址存在,则下载后进行组件扫描
    if gitlab_projects:
        for g in gitlab_projects:
            project_url = g['project_url']
            project_branch = g['project_branch']
            project_name, download_path = get_gitlab_project_codes(project_url=project_url, ref=project_branch)
            depend_report_path = excute_depend_check(project_name, download_path, scan_js=scan_js)
            word_report = analyze_report(project_name=project_name, report_path=depend_report_path)
    # 如果本地目录路径存在, 则扫描本地目录
    if local_dirs:
        for local_dir in local_dirs:
            project_name = os.path.basename(local_dir)
            depend_report_path = excute_depend_check(project_name, local_dir, scan_js=scan_js)
            word_report = analyze_report(project_name=project_name, report_path=depend_report_path)

    # 如果gitlab库存在且配置的账户密码等信息
    if gitlab_libs:
        for gitlab_lab in gitlab_libs:
            gitlab_url = gitlab_lab['gitlab_url']
            gitlab_private_token = gitlab_lab['gitlab_private_token']
            projects = get_gitlab_projects(gitlab_url, gitlab_private_token)
            for project in projects:
                project_url = project.ssh_url_to_repo
                project_branch = project.default_branch
                project_name, download_path = get_gitlab_project_codes(project_url=project_url, ref=project_branch)
                depend_report_path = excute_depend_check(project_name, download_path, scan_js=scan_js)
                word_report = analyze_report(project_name=project_name, report_path=depend_report_path)
