# This is my own Python script to query
# VirusTotal's Passive DNS database
# You'll need to regsiter for your own API Key
#
# This will query a domain name (not IP) that you feed it
# And then produce specific output files with the
# domain name appended to the title
#
# Tom Yarrish
# Version 0.5
import requests


def query_vt(api, domain):
    vt_url = 'https://www.virustotal.com/vtapi/v2/domain/report'
    vt_params = {'domain': domain, 'apikey': api}
    vt_request = requests.get(vt_url, params=vt_params)
    return vt_request.json()


# Here are going to pull out any SHA-256 samples from the output
# this will also format the output file so you can import it
# into X-Ways Forensics
def pull_hashes(samples, filename, domain):
    output_file = '{}_{}.txt'.format(domain, filename)
    with open(output_file, 'w') as output:
        output.write('SHA-256\n')
        for item in samples:
            output.write('{}\n'.format(item['sha256']))
    return


# This function pulls out the IP address and when it was last resolved
def parse_resolutions(resolution, domain):
    output_file = '{}_resolutions.txt'.format(domain)
    with open(output_file, 'w') as output:
        for item in resolution:
            output.write('IP: {}\tDate: {}\n'.format(item['ip_address'], item['last_resolved']))
    return


# This function pulls out the detected URL's and the
# date they were scanned
def parse_detected_urls(urls, domain):
    output_file = '{}_detected_urls.txt'.format(domain)
    with open(output_file, 'w') as output:
        for item in urls:
            output.write('Scan Date: {}\tURL: {}\n'.format(item['scan_date'], item['url']))
    return


def main():
    # Load up API key
    vt_api = ''

    # Prompt for domain name
    domain_query = input('What domain are you looking for? ')

    # Query VT for passive DNS
    vt_results = query_vt(vt_api, domain_query)

    # display the results
    for key, value in vt_results.items():
        print('{} -> {}'.format(key, value))
# There's probably a better way to do the following try/except statements
# But basically if the output isn't there I'm moving on.
    try:
        pull_hashes(vt_results['detected_referrer_samples'], 'detected_samples', domain_query)
    except:
        pass

    try:
        pull_hashes(vt_results['undetected_referrer_samples'], 'undetected_samples', domain_query)
    except:
        pass

    try:
        pull_hashes(vt_results['undetected_downloaded_samples'], 'undetected_downloaded_samples', domain_query)
    except:
        pass

    try:
        pull_hashes(vt_results['detected_communicating_samples'], 'detected_communicating_samples', domain_query)
    except:
        pass

    try:
        parse_resolutions(vt_results['resolutions'], domain_query)
    except:
        pass

    try:
        parse_detected_urls(vt_results['detected_urls'], domain_query)
    except:
        pass


    return


if __name__ == '__main__':
    main()
