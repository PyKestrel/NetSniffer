chrome.runtime.onInstalled.addListener(function() {
    chrome.contextMenus.create({
        "title": 'Search Target Domain: "%s"',
        "contexts": ["selection"],
        "id": "myContextMenuId"
    });
    chrome.contextMenus.create({
        "title": 'Search On Virus Total',
        "contexts": ["selection"],
        "parentId": "myContextMenuId",
        "id": "VirusTotal"
    });
    chrome.contextMenus.create({
        "title": 'Search On Talos',
        "contexts": ["selection"],
        "parentId": "myContextMenuId",
        "id": "Talos"
    });
    chrome.contextMenus.create({
        "title": 'Search On Umbrella',
        "contexts": ["selection"],
        "parentId": "myContextMenuId",
        "id": "Umbrella"
    });
    chrome.contextMenus.create({
        "title": 'Search On Censys',
        "contexts": ["selection"],
        "parentId": "myContextMenuId",
        "id": "Censys-Search"
    });

    //Search Links
    chrome.contextMenus.create({
        "title": 'Search Target Link',
        "contexts": ["link"],
        "id": "Link"
    });

    chrome.contextMenus.create({
        "title": 'Search Link On Talos',
        "contexts": ["link"],
        "parentId":"Link",
        "id": "Talos-Link"
    });

    chrome.contextMenus.create({
        "title": 'Search Link On Virus Total',
        "contexts": ["link"],
        "parentId":"Link",
        "id": "VirusT-Link"
    });

    chrome.contextMenus.create({
        "title": 'Search Link On Censys',
        "contexts": ["link"],
        "parentId":"Link",
        "id": "Censys-Link"
    });
    
    //Search CVE
    chrome.contextMenus.create({
        "title": 'Search CVE: "%s"',
        "contexts": ["selection"],
        "id": "CVE"
    });

    //NSLOOKUP
    chrome.contextMenus.create({
        "title": 'NSLOOKUP: "%s"',
        "contexts": ["selection"],
        "id": "NSLOOKUP"
    });

    //MXTOOLBOX
    chrome.contextMenus.create({
        "title": 'MXTOOLBOX',
        "contexts": ["selection"],
        "id": "MXTOOLBOX"
    });

    chrome.contextMenus.create({
        "title": 'MX Lookup',
        "contexts": ["selection"],
        "parentId":"MXTOOLBOX",
        "id": "MX-Lookup"
    });

    chrome.contextMenus.create({
        "title": 'Blacklist',
        "contexts": ["selection"],
        "parentId":"MXTOOLBOX",
        "id": "MX-Blacklist"
    });

    chrome.contextMenus.create({
        "title": 'Reverse Lookup',
        "contexts": ["selection"],
        "parentId":"MXTOOLBOX",
        "id": "MX-Reverse"
    });

    chrome.contextMenus.create({
        "title": 'Whois',
        "contexts": ["selection"],
        "parentId":"MXTOOLBOX",
        "id": "MX-Whois"
    });

    //MXTOOLBOX Links

    chrome.contextMenus.create({
        "title": 'MXTOOLBOX',
        "contexts": ["link"],
        "id": "MXTOOLBOX-Links"
    });

    chrome.contextMenus.create({
        "title": 'MX Lookup',
        "contexts": ["link"],
        "parentId":"MXTOOLBOX-Links",
        "id": "MX-Lookup-Links"
    });

    chrome.contextMenus.create({
        "title": 'Blacklist',
        "contexts": ["link"],
        "parentId":"MXTOOLBOX-Links",
        "id": "MX-Blacklist-Links"
    });

    chrome.contextMenus.create({
        "title": 'Reverse Lookup',
        "contexts": ["link"],
        "parentId":"MXTOOLBOX-Links",
        "id": "MX-Reverse-Links"
    });

    chrome.contextMenus.create({
        "title": 'Whois',
        "contexts": ["link"],
        "parentId":"MXTOOLBOX-Links",
        "id": "MX-Whois-Links"
    });

    //OSINT
    chrome.contextMenus.create({
        "title": 'OSINT',
        "contexts": ["selection"],
        "id": "OSINT"
    });
    //Phone OSINT
    chrome.contextMenus.create({
        "title": 'Phone',
        "contexts": ["selection"],
        "parentId":"OSINT",
        "id": "OSINT-Phone"
    });

    //Address OSINT
    chrome.contextMenus.create({
        "title": 'Address',
        "contexts": ["selection"],
        "parentId":"OSINT",
        "id": "OSINT-Address"
    });

    //Geo IP OSINT
    chrome.contextMenus.create({
        "title": 'Geo-IP',
        "contexts": ["selection"],
        "parentId":"OSINT",
        "id": "OSINT-GeoIP"
    });

    chrome.contextMenus.create({
        "title": 'IP2LOCATION',
        "contexts": ["selection"],
        "parentId":"OSINT-GeoIP",
        "id": "IP2LOCATION"
    });
    //Finance OSINT
    chrome.contextMenus.create({
        "title": 'Finance',
        "contexts": ["selection"],
        "parentId":"OSINT",
        "id": "OSINT-Finance"
    });
    //IOT Osint
    chrome.contextMenus.create({
        "title": 'IOT',
        "contexts": ["selection"],
        "parentId":"OSINT",
        "id": "OSINT-IOT"
    });
    chrome.contextMenus.create({
        "title": 'Censys',
        "contexts": ["selection"],
        "parentId":"OSINT-IOT",
        "id": "Censys"
    });

    /*
    // Social Media OSINT
    chrome.contextMenus.create({
        "title": 'Social Media',
        "contexts": ["selection"],
        "parentId":"OSINT",
        "id": "OSINT-SM"
    });

    chrome.contextMenus.create({
        "title": 'LinkedIn',
        "contexts": ["selection"],
        "parentId":"OSINT-SM",
        "id": "OSINT-LI"
    });

    */

    // Scrape Page
    chrome.contextMenus.create({
        "title": 'Scrape Page',
        "contexts": ["page"],
        "id": "scrapePage"
    });
});
    
chrome.contextMenus.onClicked.addListener(async function(info, tab) {
    if(info.menuItemId == "VirusTotal"){
        if(/^(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/.test(info.selectionText)){
            chrome.tabs.create({  
                url: "https://www.virustotal.com/gui/ip-address/" + encodeURIComponent(info.selectionText)
            });
        }else{
            chrome.tabs.create({  
            url: "https://www.virustotal.com/gui/domain/" + encodeURIComponent(info.selectionText)
            });
        }
    }
    if(info.menuItemId == "VirusT-Link"){
        if(/^(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/.test(info.selectionText)){
            chrome.tabs.create({  
                url: "https://www.virustotal.com/gui/ip-address/" + encodeURIComponent(info.linkUrl)
            });
        }else{
            chrome.tabs.create({  
            url: "https://www.virustotal.com/gui/domain/" + encodeURIComponent(info.linkUrl.replace(/^(?:https?:\/\/)?(?:[^\/]+\.)?([^.\/]+\.[^.\/]+).*$/, "$1"))
            });
        }
    }
    if(info.menuItemId == "Talos"){
        chrome.tabs.create({  
            url: "https://www.talosintelligence.com/reputation_center/lookup?search=" + encodeURIComponent(info.selectionText)
        });
    }
    if(info.menuItemId == "Talos-Link"){
        chrome.tabs.create({  
            url: "https://www.talosintelligence.com/reputation_center/lookup?search=" + encodeURIComponent(info.linkUrl)
        });
    }
    if(info.menuItemId == "Umbrella"){
        chrome.tabs.create({  
            url: "https://investigate.umbrella.com/ip-view/" + encodeURIComponent(info.selectionText)
        });
    }
    
    //CVE Search
    if(info.menuItemId == "CVE"){
        if(/^CVE-[0-9][0-9][0-9][0-9]-[0-9][0-9][0-9][0-9][0-9]$/i){
            chrome.tabs.create({  
                url: "https://cve.mitre.org/cgi-bin/cvename.cgi?name=" + encodeURIComponent(info.selectionText)
            });
        }
        else{
            alert("Enter Valid CVE Format: Ex. CVE-2022-33075")
        }
        
    }

    //NSLOOKUP
    if(info.menuItemId == "NSLOOKUP"){
        chrome.tabs.create({  
            url: "https://www.nslookup.io/domains/" + encodeURIComponent(info.selectionText) + "/dns-records/"
        });
    }

    //MXTOOLBOX
    if(info.menuItemId == "MX-Lookup"){
        chrome.tabs.create({  
            url: "https://mxtoolbox.com/SuperTool.aspx?action=mx%3a" + encodeURIComponent(info.selectionText) + "&run=toolpage"
        });
    }

    if(info.menuItemId == "MX-Blacklist"){
        chrome.tabs.create({  
            url: "https://mxtoolbox.com/SuperTool.aspx?action=mx%3a" + encodeURIComponent(info.selectionText) + "&run=networktools"
        });
    }

    if(info.menuItemId == "MX-Reverse"){
        chrome.tabs.create({  
            url: "https://mxtoolbox.com/SuperTool.aspx?action=ptr%3a" + encodeURIComponent(info.selectionText) + "&run=networktools"
        });
    }

    if(info.menuItemId == "MX-Blacklist"){
        chrome.tabs.create({  
            url: "https://mxtoolbox.com/SuperTool.aspx?action=whois%3a" + encodeURIComponent(info.selectionText) + "&run=networktools"
        });
    }

    //MXTOOLBOX Links
    if(info.menuItemId == "MX-Lookup-Links"){
        chrome.tabs.create({  
            url: "https://mxtoolbox.com/SuperTool.aspx?action=mx%3a" + encodeURIComponent(info.linkUrl.replace(/^(?:https?:\/\/)?(?:[^\/]+\.)?([^.\/]+\.[^.\/]+).*$/, "$1")) + "&run=toolpage"
        });
    }

    if(info.menuItemId == "MX-Blacklist-Links"){
        chrome.tabs.create({  
            url: "https://mxtoolbox.com/SuperTool.aspx?action=mx%3a" + encodeURIComponent(info.linkUrl.replace(/^(?:https?:\/\/)?(?:[^\/]+\.)?([^.\/]+\.[^.\/]+).*$/, "$1")) + "&run=networktools"
        });
    }

    if(info.menuItemId == "MX-Reverse-Links"){
        chrome.tabs.create({  
            url: "https://mxtoolbox.com/SuperTool.aspx?action=ptr%3a" + encodeURIComponent(info.linkUrl.replace(/^(?:https?:\/\/)?(?:[^\/]+\.)?([^.\/]+\.[^.\/]+).*$/, "$1")) + "&run=networktools"
        });
    }

    if(info.menuItemId == "MX-Blacklist-Links"){
        chrome.tabs.create({  
            url: "https://mxtoolbox.com/SuperTool.aspx?action=whois%3a" + encodeURIComponent(info.linkUrl.replace(/^(?:https?:\/\/)?(?:[^\/]+\.)?([^.\/]+\.[^.\/]+).*$/, "$1")) + "&run=networktools"
        });
    }

    //OSINT

    //Geo IP OSINT
    if(info.menuItemId == "IP2LOCATION"){
        chrome.scripting.executeScript({
            code: 'console.log("Hello")'
          });
    }
    //IOT
    if(info.menuItemId == "Censys" || info.menuItemId == "Censys-Search"){
        if(/^(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/.test(info.selectionText)){
            chrome.tabs.create({  
                url: "https://search.censys.io/hosts/" + encodeURIComponent(info.selectionText)
            });
        }else{
            chrome.tabs.create({  
            url: "https://search.censys.io/search?resource=hosts&sort=RELEVANCE&per_page=25&virtual_hosts=EXCLUDE&q=" + encodeURIComponent(info.selectionText)
            });
        }
    }

    if(info.menuItemId == "Censys-Link"){
        if(/^(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/.test(info.selectionText)){
            chrome.tabs.create({  
                url: "https://search.censys.io/hosts/" + encodeURIComponent(info.linkUrl)
            });
        }else{
            chrome.tabs.create({  
            url: "https://search.censys.io/search?resource=hosts&sort=RELEVANCE&per_page=25&virtual_hosts=EXCLUDE&q=" + encodeURIComponent(info.linkUrl.replace(/^(?:https?:\/\/)?(?:[^\/]+\.)?([^.\/]+\.[^.\/]+).*$/, "$1"))
            });
        }
    }


    //Social Media OSINT


    // LinkedIn OSINT
    /*
    let LinkedInToken = "" 
    if(info.menuItemId == "OSINT-LI"){
        const response =  await fetch("https://api.linkedin.com/v2/companySearch?q=" + encodeURIComponent(info.linkUrl), {
            headers: {
            Authorization: "Bearer {"+LinkedInToken+"}"
                }
        })
        var data = await response.json();
        var json = JSON.stringify(data),
        blob = new Blob([json], {type: "octet/stream"}),
        url = window.URL.createObjectURL(blob);
        fileName = "linkedin.json";
        a.href = url;
        a.download = fileName;
        a.click();
        window.URL.revokeObjectURL(url);
    }
    */

    // Active Tab Scraper
    /*
    Scrape Any Data Of Interest With Pre-Defined Regex Expressions That Look For Street Addresses, IP Addresses, Domain Names & More
    Because There Isnt Really Anysort Of Intelligence Associated With This, You May Find Yorself Receiving Useless Information But This Will Continue To Be Improved Upon.

    Permissions Needed: Scripting

    Reason: Needed To Access The Entire DOM
    */
    if(info.menuItemId == "scrapePage"){
        chrome.tabs.query({active: true, currentWindow: true},function(tabs){   
            var currentTab = tabs[0];
            function scrapePage(){
                let page = document.documentElement.innerHTML;
                let ip =  page.match(/(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)/g);
                let domains = page.match(/href="([^"]*)/g);
                let usPhoneNumbers = page.match(/(?:^|\D)\(([2-9])(?:\d(?!\1)\d|(?!\1)\d\d)\)\s*[2-9]\d{2}-\d{4}/g)
                // let ukPhoneNumbers = page.match(/^(((\+44\s?\d{4}|\(?0\d{4}\)?)\s?\d{3}\s?\d{3})|((\+44\s?\d{3}|\(?0\d{3}\)?)\s?\d{3}\s?\d{4})|((\+44\s?\d{2}|\(?0\d{2}\)?)\s?\d{4}\s?\d{4}))(\s?\#(\d{4}|\d{3}))?$/g)
                // let frPhoneNumbers = page.match(/^(?:(?:\+|00)33[\s.-]{0,3}(?:\(0\)[\s.-]{0,3})?|0)[1-9](?:(?:[\s.-]?\d{2}){4}|\d{2}(?:[\s.-]?\d{3}){2})$/g)
                // let dePhoneNumbers = page.match(/(\(?([\d \-\)\–\+\/\(]+){6,}\)?([ .\-–\/]?)([\d]+))/g)
                // let cnPhoneNumbers = page.match(/^(?:(?:\d{3}-)?\d{8}|^(?:\d{4}-)?\d{7,8})(?:-\d+)?$/g)
                // let inPhoneNumbers = page.match(/((\+*)((0[ -]*)*|((91 )*))((\d{12})+|(\d{10})+))|\d{5}([- ]*)\d{6}/g)
                // let brPhoneNumbers = page.match(/\(([0-9]{2}|0{1}((x|[0-9]){2}[0-9]{2}))\)\s*[0-9]{3,4}[- ]*[0-9]{4}/g)
                // let auPhoneNumbers = page.match(/(^1300\d{6}$)|(^1800|1900|1902\d{6}$)|(^0[2|3|7|8]{1}[0-9]{8}$)|(^13\d{4}$)|(^04\d{2,3}\d{6}$)/g)
                // let nlPhoneNumbers = page.match(/(^\+[0-9]{2}|^\+[0-9]{2}\(0\)|^\(\+[0-9]{2}\)\(0\)|^00[0-9]{2}|^0)([0-9]{9}$|[0-9\-\s]{10}$)/g)
                let scrap = [ip, domains, usPhoneNumbers]
                console.log(scrap)
                let resultsDiv = document.createElement("div");
                resultsDiv.style.width = "100%"
                resultsDiv.style.minHeight = "300px"
                resultsDiv.style.backgroundColor = "white"
                /*
                
                    Other National Numbers Code:

                    <td>UK Phone Numbers</td><td>French Phone Numbers</td><td>German Phone Numbers</td><td>Chinese Phone Numbers</td><td>Indian Phone Numbers</td><td>Brazilian Phone Numbers</td><td>Australian Phone Numbers</td><td>Dutch Phone Numbers</td>
                    <td>" + maxArray[3][index] + "</td><td>" + maxArray[4][index] + "</td><td>" + maxArray[5][index] + "</td><td>" + maxArray[6][index] + "</td><td>" + maxArray[7][index] + "</td><td>" + maxArray[8][index] + "</td><td>" + maxArray[9][index] + "</td><td>" + maxArray[10][index] + "</td>


                */
                document.querySelector('header').innerHTML += "<style>table {border-collapse: collapse;min-width: 50%;}th, td {text-align: left;padding: 8px;} tr {border-bottom: 1px solid #ddd;}tr:nth-child(even) {background-color: #D6EEEE;}</style>"
                resultsDiv.innerHTML += "<table id='resTable' style='border-spacing: 30px; margin-left:auto; margin-right:auto;'><tr><td style='margin-left:10px; margin-right:10px;'>IP Addresses</td><td style='margin-left:10px; margin-right:10px;'>Domain Names</td><td style='margin-left:10px; margin-right:10px;'>US Phone Numbers</td></tr></table>"
                let maxArray = 0;
                document.body.insertAdjacentElement("afterbegin", resultsDiv);
                for (let index = 0; index < scrap.length; index++) {
                    if(scrap[index]?.length){
                        if(scrap[index].length > maxArray){
                            maxArray = scrap[index].length
                        }else{
                            continue
                        }  
                    }
                }
                console.log(maxArray)
                for (let index = 0; index < maxArray; index++) {
                    document.getElementById("resTable").innerHTML += "<tr><td>" + scrap[0]?.[index] + "</td><td>" + scrap[1]?.[index].replace('href="','') + "</td><td>" + scrap[2]?.[index] + "</td></tr>"
                }
                
            }
            chrome.scripting.executeScript(
                {
                  target: {tabId: currentTab.id},
                  func: scrapePage,
                });
        });
        
        }

})