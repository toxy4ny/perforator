#!/usr/bin/env python3
"""
S3 Bucket Enumeration Script for Pentesting

"""

import requests
import xml.etree.ElementTree as ET
from concurrent.futures import ThreadPoolExecutor, as_completed
import argparse
from urllib.parse import urljoin
import time
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
import os

LOGO = r"""

 ____  _____ ____  _____ ____  ____  ____ _____ ____  ____ 
/  __\/  __//  __\/    //  _ \/  __\/  _ Y__ __Y  _ \/  __\
|  \/||  \  |  \/||  __\| / \||  \/|| / \| / \ | / \||  \/|
|  __/|  /_ |    /| |   | \_/||    /| |-|| | | | \_/||    /
\_/   \____\\_/\_\\_/   \____/\_/\_\\_/ \| \_/ \____/\_/\_\
                                                           
By KL3FT3Z (https://github.com/toxy4ny)
"""

def banner():

    os.system("cls" if os.name == "nt" else "clear")
    print(LOGO)
    print("😈 S3 Bucket Enumeration Script for Pentesting\n")


class S3Enumerator:
    def __init__(self, base_url, timeout=10, max_workers=20):
        self.base_url = base_url.rstrip('/')
        self.timeout = timeout
        self.max_workers = max_workers
        self.session = self._create_session()
        
        self.common_objects = [
            'index.html', 'index.htm', 'default.html',
            'config.json', 'config.js', 'config.xml', 'config.yml', 'config.yaml',
            'app.js', 'main.js', 'bundle.js', 'app.min.js',
            'main.css', 'style.css', 'app.css', 'styles.css',
            'manifest.json', 'package.json', 'composer.json',
            '.env', '.env.local', '.env.production', '.env.development',
            'settings.json', 'settings.js', 'settings.xml',
            'database.yml', 'database.json', 'db.json',
            'backup.sql', 'dump.sql', 'database.sql',
            'users.json', 'users.xml', 'userlist.txt',
            'api.json', 'endpoints.json', 'routes.json',
            'keys.json', 'secrets.json', 'credentials.json',
            'error.log', 'access.log', 'debug.log',
            'robots.txt', 'sitemap.xml', '.htaccess',
            'README.md', 'README.txt', 'CHANGELOG.md',
            'version.txt', 'VERSION', 'build.json',
            'swagger.json', 'openapi.json', 'api-docs.json'
        ]
        
        self.common_directories = [
            'static', 'assets', 'js', 'css', 'img', 'images',
            'uploads', 'files', 'docs', 'backup', 'backups',
            'admin', 'api', 'app', 'src', 'public',
            'private', 'internal', 'logs', 'tmp', 'temp',
            'cache', 'data', 'db', 'config', 'conf'
        ]
        
        self.bucket_patterns = [
   
            'assets', 'uploads', 'static', 'media', 'files',
            'backups', 'logs', 'data', 'config', 'docs'
        ]

    def _create_session(self):
        
        session = requests.Session()
        retry_strategy = Retry(
            total=3,
            status_forcelist=[429, 500, 502, 503, 504],
            method_whitelist=["HEAD", "GET", "OPTIONS"]
        )
        adapter = HTTPAdapter(max_retries=retry_strategy)
        session.mount("http://", adapter)
        session.mount("https://", adapter)
        return session

    def check_bucket_existence(self, bucket_name):
       
        endpoints = [
            f"{self.base_url}/{bucket_name}",
            f"{self.base_url}/{bucket_name}/",
            f"{self.base_url}/{bucket_name}?list-type=2&max-keys=1",
            f"{self.base_url}/{bucket_name}?max-keys=1"
        ]
        
        results = {}
        for endpoint in endpoints:
            try:
                response = self.session.head(endpoint, timeout=self.timeout)
                results[endpoint] = {
                    'status': response.status_code,
                    'headers': dict(response.headers),
                    'exists': response.status_code != 404
                }
                
                if response.status_code not in [404, 403]:
                    
                    get_response = self.session.get(endpoint, timeout=self.timeout)
                    results[endpoint]['content'] = get_response.text[:500]
                    results[endpoint]['content_length'] = len(get_response.content)
                    
            except Exception as e:
                results[endpoint] = {'error': str(e)}
                
        return bucket_name, results

    def list_bucket_contents(self, bucket_name):
        
        list_endpoints = [
            f"{self.base_url}/{bucket_name}?list-type=2&max-keys=1000",
            f"{self.base_url}/{bucket_name}?max-keys=1000",
            f"{self.base_url}/{bucket_name}?delimiter=/",
            f"{self.base_url}/{bucket_name}/"
        ]
        
        for endpoint in list_endpoints:
            try:
                response = self.session.get(endpoint, timeout=self.timeout)
                if response.status_code == 200:
                    return self._parse_s3_response(response.text)
            except Exception as e:
                continue
        return []

    def _parse_s3_response(self, xml_content):
       
        objects = []
        try:
            root = ET.fromstring(xml_content)
            
            namespaces = {'s3': 'http://s3.amazonaws.com/doc/2006-03-01/'}
            
            for content in root.findall('.//Contents') or root.findall('.//s3:Contents', namespaces):
                key_elem = content.find('Key') or content.find('s3:Key', namespaces)
                size_elem = content.find('Size') or content.find('s3:Size', namespaces)
                modified_elem = content.find('LastModified') or content.find('s3:LastModified', namespaces)
                
                if key_elem is not None:
                    objects.append({
                        'key': key_elem.text,
                        'size': size_elem.text if size_elem is not None else 'Unknown',
                        'last_modified': modified_elem.text if modified_elem is not None else 'Unknown'
                    })
        except ET.ParseError:
            
            if '<a href=' in xml_content:
                import re
                links = re.findall(r'<a href="([^"]+)"', xml_content)
                objects = [{'key': link, 'size': 'Unknown', 'last_modified': 'Unknown'} for link in links]
                
        return objects

    def check_object_access(self, bucket_name, object_name):
       
        url = f"{self.base_url}/{bucket_name}/{object_name}"
        try:
            response = self.session.head(url, timeout=self.timeout)
            result = {
                'url': url,
                'status': response.status_code,
                'size': response.headers.get('Content-Length', 'Unknown'),
                'content_type': response.headers.get('Content-Type', 'Unknown'),
                'accessible': response.status_code == 200
            }
            
            if response.status_code == 200:
                
                get_response = self.session.get(url, timeout=self.timeout)
                result['content_preview'] = get_response.text[:200]
                result['is_sensitive'] = self._is_sensitive_content(object_name, get_response.text)
                
            return result
        except Exception as e:
            return {'url': url, 'error': str(e)}

    def _is_sensitive_content(self, filename, content):
     
        sensitive_patterns = [
            'password', 'secret', 'key', 'token', 'credential',
            'database', 'connection', 'mysql', 'postgres', 'mongodb',
            'api_key', 'private_key', 'access_token', 'bearer',
            'smtp_', 'mail_', 'email_password'
        ]
        
        sensitive_extensions = ['.env', '.sql', '.json', '.xml', '.yml', '.yaml']
        
      
        filename_lower = filename.lower()
        if any(ext in filename_lower for ext in sensitive_extensions):
            return True
            
      
        content_lower = content[:1000].lower()
        return any(pattern in content_lower for pattern in sensitive_patterns)

    def enumerate_buckets(self):
      
        print(f"🔍 Starting S3 enumeration on {self.base_url}")
        print(f"📊 Checking {len(self.bucket_patterns)} potential buckets...")
        
        accessible_buckets = []
        
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            future_to_bucket = {
                executor.submit(self.check_bucket_existence, bucket): bucket 
                for bucket in self.bucket_patterns
            }
            
            for future in as_completed(future_to_bucket):
                bucket_name = future_to_bucket[future]
                try:
                    bucket_name, results = future.result()
                    
                  
                    accessible = False
                    best_result = None
                    
                    for endpoint, result in results.items():
                        if 'error' not in result and result.get('exists', False):
                            accessible = True
                            if result['status'] == 200:
                                best_result = result
                                break
                            elif best_result is None or result['status'] < best_result['status']:
                                best_result = result
                    
                    if accessible:
                        accessible_buckets.append({
                            'name': bucket_name,
                            'result': best_result,
                            'all_results': results
                        })
                        print(f"✅ Found accessible bucket: {bucket_name} (Status: {best_result['status']})")
                    else:
                        print(f"❌ {bucket_name}: Not accessible")
                        
                except Exception as e:
                    print(f"⚠️ Error checking {bucket_name}: {e}")
        
        return accessible_buckets

    def enumerate_objects_in_bucket(self, bucket_name):
        
        print(f"\n🔍 Enumerating objects in bucket: {bucket_name}")
        
       
        print("📋 Attempting to list bucket contents...")
        objects = self.list_bucket_contents(bucket_name)
        
        if objects:
            print(f"✅ Found {len(objects)} objects via listing:")
            for obj in objects[:10]: 
                print(f"  📄 {obj['key']} ({obj['size']} bytes)")
            if len(objects) > 10:
                print(f"  ... and {len(objects) - 10} more objects")
        else:
            print("❌ No objects found via listing, trying brute-force...")
            
       
        print(f"🔨 Brute-forcing {len(self.common_objects)} common objects...")
        found_objects = []
        
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            future_to_object = {
                executor.submit(self.check_object_access, bucket_name, obj): obj 
                for obj in self.common_objects
            }
            
            for future in as_completed(future_to_object):
                object_name = future_to_object[future]
                try:
                    result = future.result()
                    if result.get('accessible', False):
                        found_objects.append(result)
                        sensitivity = "🔥 SENSITIVE" if result.get('is_sensitive', False) else "📄 Regular"
                        print(f"✅ {sensitivity}: {object_name} ({result['size']} bytes)")
                        
                       
                        if result.get('is_sensitive', False) and 'content_preview' in result:
                            print(f"   Preview: {result['content_preview'][:100]}...")
                            
                except Exception as e:
                    pass  
        
       
        print(f"📁 Checking {len(self.common_directories)} common directories...")
        for directory in self.common_directories:
            try:
                dir_objects = self.list_bucket_contents(f"{bucket_name}/{directory}")
                if dir_objects:
                    print(f"📁 Found directory: {directory}/ with {len(dir_objects)} objects")
            except:
                pass
        
        return objects + found_objects

    def full_enumeration(self):
       
        print("🚀 Starting full S3 enumeration")
        print("=" * 60)
        
        
        accessible_buckets = self.enumerate_buckets()
        
        if not accessible_buckets:
            print("\n❌ No accessible buckets found")
            return
        
        print(f"\n✅ Found {len(accessible_buckets)} accessible buckets")
        print("=" * 60)
        
       
        all_findings = {}
        for bucket_info in accessible_buckets:
            bucket_name = bucket_info['name']
            objects = self.enumerate_objects_in_bucket(bucket_name)
            all_findings[bucket_name] = {
                'bucket_info': bucket_info,
                'objects': objects
            }
            print("\n" + "=" * 60)
        
        
        self.generate_report(all_findings)
        
        return all_findings

    def generate_report(self, findings):
      
        print("\n📊 ENUMERATION REPORT")
        print("=" * 80)
        
        total_buckets = len(findings)
        total_objects = sum(len(bucket_data['objects']) for bucket_data in findings.values())
        sensitive_objects = []
        
        for bucket_name, bucket_data in findings.items():
            print(f"\n🪣 BUCKET: {bucket_name}")
            print(f"   Status: {bucket_data['bucket_info']['result']['status']}")
            print(f"   Objects found: {len(bucket_data['objects'])}")
            
            for obj in bucket_data['objects']:
                if isinstance(obj, dict) and obj.get('is_sensitive', False):
                    sensitive_objects.append(f"{bucket_name}/{obj.get('key', obj.get('url', 'unknown'))}")
                    print(f"   🔥 SENSITIVE: {obj.get('key', obj.get('url', 'unknown'))}")
        
        print(f"\n📈 SUMMARY:")
        print(f"   Total accessible buckets: {total_buckets}")
        print(f"   Total objects found: {total_objects}")
        print(f"   Sensitive objects: {len(sensitive_objects)}")
        
        if sensitive_objects:
            print(f"\n🔥 SENSITIVE FILES FOUND:")
            for sensitive_file in sensitive_objects:
                print(f"   - {sensitive_file}")


def main():
    banner()
    parser = argparse.ArgumentParser(description='S3 Bucket Enumeration Tool')
    parser.add_argument('--url', default='https://storage.example.com', 
                       help='Base S3 endpoint URL')
    parser.add_argument('--bucket', help='Specific bucket to enumerate')
    parser.add_argument('--timeout', type=int, default=10, help='Request timeout')
    parser.add_argument('--workers', type=int, default=20, help='Max concurrent workers')
    
    args = parser.parse_args()
    
    enumerator = S3Enumerator(args.url, timeout=args.timeout, max_workers=args.workers)
    
    if args.bucket:
        
        print(f"🎯 Targeting specific bucket: {args.bucket}")
        objects = enumerator.enumerate_objects_in_bucket(args.bucket)
        print(f"\n✅ Found {len(objects)} objects in {args.bucket}")
    else:
       
        enumerator.full_enumeration()


if __name__ == "__main__":
    main()