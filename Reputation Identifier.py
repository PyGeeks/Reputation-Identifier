import pandas as pd, requests
class comman_class():
    def __init__(self, apikey):
        self.apikey = apikey
    def error_code(self, status_code):
        if status_code == 204:
            return 'Request rate limit exceeded'
        elif status_code == 400:
            return 'Bad request'
        elif status_code == 403:
            return 'Forbidden'


class File_API(comman_class):
    def __init__(self, apikey, file):
        self.apikey = apikey
        if isinstance(file, str):
            self.file = [file]
        elif isinstance(file, list):
            self.file = file
        else:
            raise TypeError('Only List or Str format is allowed')
        super().__init__(apikey)

    def get_file_status(self, mode=False, filepath=None):
        filepath, scan_id, sha1, sha256, md5, score, permalink = [], [], [], [], [], [], []
        for f in self.file:
            file = {'file': open(f)}
            data = {'apikey': self.apikey, 'file': f}
            response = requests.post(url='https://www.virustotal.com/vtapi/v2/file/scan', files=file, data=data)
            if response.status_code == 200:
                resp = response.json()
                while True:
                    if resp['response_code'] == 1:
                        filepath.append(f)
                        scan_id.append(resp.setdefault('scan_id', 'No Info'))
                        sha1.append(resp.setdefault('sha1', 'No Info'))
                        sha256.append(resp.setdefault('sha256', 'No Info'))
                        sha_var = resp.setdefault('sha256', 'No Info')
                        md5.append(resp.setdefault('md5', 'No Info'))
                        score.append(str(resp.setdefault('positives', 'No Info')) + '/' + str(
                            resp.setdefault('total', 'No Info')))
                        permalink.append(resp.setdefault('permalink', 'No Info'))
                        break
            else:
                res = self.error_code(f.status_code)
                print(res)

        df = pd.DataFrame(
            {'FilePath': filepath, 'scan_id': scan_id, 'sha1': sha1, 'md5': md5, 'sha256': sha256, 'score': score,
             'link to virustotal': permalink})
        if mode is True:
            if filepath is not None:
                h = df.to_csv(filepath, index=False)
                return 'file created'
            else:
                print('file path must be not empty')
        else:
            return df

class Url(comman_class):
    def __init__(self, apikey, url):
        self.apikey = apikey
        if isinstance(url, str):
            self.url = [url]
        elif isinstance(url, list):
            self.url = url
        else:
            print('url is not accepted')
        super().__init__(apikey)

    def get_url(self, mode=False, filepath=None):
        url_path, scan_id, resource, url, scan_date, permalink, score, detected = [], [], [], [], [], [], [], []
        for f1 in self.url:
            a = {'apikey': self.apikey, 'url': f1}
            f = requests.post(url='https://www.virustotal.com/vtapi/v2/url/scan', params=a)
            if f.status_code == 200:
                resp = f.json()
                while True:
                    if resp['response_code'] == 1:
                        url_path.append(f1)
                        scan_id.append(resp.setdefault('scan_id', 'No Info'))
                        scan_var = resp['scan_id']
                        resource.append(resp.setdefault("resource", 'No Info'))
                        url.append(resp.setdefault("url", 'No Info'))
                        scan_date.append(resp.setdefault("scan_date", 'No Info'))

                        permalink.append(resp.setdefault("permalink", 'No Info'))
                        try:
                            a = {'apikey': self.apikey, 'resource': scan_var}
                            f2 = requests.get(url='https://www.virustotal.com/vtapi/v2/url/report', params=a).json()

                            score.append(str(f2.setdefault("positives", 'No Info')) + '/' + str(
                                f2.setdefault("positives", 'No Info')))
                            dummy_key = ''
                            for i, j in f2['scans'].items():
                                if j['detected'] is False: dummy_key = dummy_key + i
                            detected.append(dummy_key)
                        except:
                            detected.append('No Info')
                        break

        data = {'url_path': url_path, 'scan_id': scan_id, 'resource': resource, 'url': url, 'scan_date': scan_date,
                'permalink': permalink, 'score': score, 'detected': detected}
        df = pd.DataFrame(data)
        if mode is True:
            if filepath is not None:
                f3 = df.to_csv(filepath, index=False)
                return 'file created'
            else:
                print('path must be not empty')
        else:
            return df

class Domain(comman_class):
    def __init__(self, apikey, domain):
        self.apikey = apikey
        if isinstance(domain, str):
            self.domain = [domain]
        elif isinstance(domain, list):
            self.domain = domain
        else:
            print('Plz Cheak u r Domain is not in Order')
        super().__init__(apikey)

    def get_domain(self, mode=False, output_file_path=None):
        categories, trendmicro_category, domain_sibling = [], [], []
        for f in self.domain:
            a = {'apikey': self.apikey, 'domain': f}
            f = requests.get(url='https://www.virustotal.com/vtapi/v2/domain/report', params=a)
            if f.status_code == 200:
                resp = f.json()
                while True:
                    categories.append(str(resp.setdefault('categories', 'No Info')).replace('[', '').replace(']','').replace("'",''))
                    trendmicro_category.append(str(resp.setdefault('TrendMicro category', 'No Info')).replace('[','').replace(']','').replace("'",''))
                    domain_sibling.append(str(resp.setdefault("domain_siblings", 'No Info')).replace('[', '').replace(']', '').replace("'", ''))
                    break
            else:
                self.error_code(f.status_code)
        data = {'catogiries': categories, 'trendmicro_category': trendmicro_category, 'domain_sibling': domain_sibling}
        df = pd.DataFrame(data)
        if mode is True:
            if output_file_path is not None:
                df.to_csv(output_file_path, index=False)
                return 'file created'
            else:
                print('output_file_path parameter should not be None')
        elif mode is False:
            return df

class Hash(comman_class):
    def __init__(self, apikey, hash):
        self.apikey = apikey
        if isinstance(hash, str):
            self.hash = [hash]
        elif isinstance(hash, list):
            self.hash = hash
        else:
            print('hash is not acceptable ')
        super().__init__(apikey)

    def get_hash(self,mode=False,filepath=None):
        detected = []
        for f in self.hash:
            a = {'apikey': self.apikey, 'resource': f}
            resp = requests.get(url='https://www.virustotal.com/vtapi/v2/file/rescan', params=a)
            try:
                k = resp.json()
                dummy_key = ''
                for k, v in k['scans'].items():
                    if v['detected'] is False:
                        dummy_key = dummy_key + k
                detected.append(dummy_key)
            except:
                detected.append('No Info')

        data = {'detected': detected}
        df = pd.DataFrame(data)
        if mode is True:
            if filepath is not None:
                f6 = df.to_csv(filepath, index=False)
                return 'file created'
            else:print('file path should not be empty')
        else :return df

class Final:

    def main(self):
        print('Welcome to Virus Total ')
        api_key = input('Please Enter your Virus Total API Key : ')
        print('*Choose u r choice\n1.Domain_check\n2.file_scan_Check\n3.url_check\n4.hash_check')
        choice=input('*choose choice:')
        if choice == '1':
            print('You Selected Domain')
            print('1. Single Domain\n2. Multiple Domain')
            usr_choice = input('Enter your choice : ')
            if usr_choice == '1':
                domain = input('Enter your domain : ')
                d = Domain(apikey=api_key, domain=domain)
                print(d.get_domain())
            elif usr_choice == '2':
                file_choice = input('Do you want to create file with response [Y/N] : ')
                if file_choice in ['Y', 'y']:
                    file_name = input('Enter Output File Path : ')
                    domain = input('Enter your domains separated by comma : ').split(',')
                    d = Domain(apikey=api_key, domain=domain)

                    print(d.get_domain(mode=True, output_file_path=file_name))
                    if d.get_domain() is True: print('file created')
                elif file_choice in ['N', 'n']:
                    domain = [dom.strip() for dom in input('Enter your domains separated by comma : ').split(',')]
                    d = Domain(apikey=api_key, domain=domain)
                    print(d.get_domain())
        elif choice=='2':
            print('your selected file')
            print('1.single file\n2.multiple files')
            file_choice=input('enter choice:')
            if file_choice=='1':
                file=input('enter file:')
                f=File_API(apikey=api_key,file=file)
                print(f.get_file_status())
            elif file_choice=='2':
                file_choice = input('Do you want to create file with response [Y/N] : ')
                if file_choice in ['Y', 'y']:
                    file=input('enter files by comma searated:').split(',')
                    f=File_Api(apikey=api_key,file=file)
                    file_name=input('enter file path')
                    print(d.get_file_status(mode=True,filepath=file_name))
                elif file_choice in ['N','n']:
                    file = [dom.strip() for dom in input('Enter your file separated by comma : ').split(',')]
                    d = File_Api(apikey=api_key, file=file)
                    print(d.get_file_status())
        elif choice=='3':
            print('your selected url ')
            print('1.single url\n2.multiple url')
            choice=input('enter choice')
            if choice == '1':
                url=input('enter url')
                d=Url(apikey=api_key,url=url)
                print(d.get_url())
            elif choice== '2':
                file_choice=input('do you want file with response[Y/N]')
                if file_choice in ['Y','y']:
                    url1=input('enter urls by comma separated').split(',')
                    f=Url(apikey=api_key,url=url1)
                    file_path=input('enter file path')
                    print(f.get_url(mode=True,filepath=file_path))
                elif file_choice in ['N','n']:
                    url = [dom.strip() for dom in input('Enter your file separated by comma : ').split(',')]
                    d = File_Api(apikey=api_key, file=url)
                    print(d.get_url())
        elif choice=='4':
            print('enter u r selcted hash')
            print('1.sigle hash\n2.multiple hash')
            choice=input('enter u r choice')
            if choice == '1':
                hash=input('enter hash_value')
                a=Hash(apikey=api_key,hash=hash)
                print(a.get_hash())
            elif choice=='2':
                choice=input('do you want file with response[Y/N]')
                if choice in ['Y','y']:
                    hash=input('enter hash values separated by comma').split(',')
                    filepath=input('enter file path')
                    d=Hash(apikey=api_key,hash=hash)
                    print(d.get_hash(mode=True,filepath=filepath))
                elif choice in ['N','n']:
                    hash = [dom.strip() for dom in input('Enter your file separated by comma : ').split(',')]
                    d=Hash(apikey=api_key,hash=hash)
                    print(d.get_hash())



vt = Final()
try:
    vt.main()
except requests.exceptions.ConnectionError:  print('No Internet Connection Unable to Perfom API Call')
except PermissionError: print('Unable to Create the file, because the same file is opened!')

