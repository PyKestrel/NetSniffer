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
    
    // Talos
    chrome.contextMenus.create({
        "title": 'Search Link On Talos',
        "contexts": ["link"],
        "parentId":"Link",
        "id": "Talos-Link"
    });
    //Talos Sanitize Link
    chrome.contextMenus.create({
        "title": 'Sanitize',
        "contexts": ["link"],
        "parentId":"Talos-Link",
        "id": "T-Sanitize"
    });

    //Virus Total Link
    chrome.contextMenus.create({
        "title": 'Search Link On Virus Total',
        "contexts": ["link"],
        "parentId":"Link",
        "id": "VirusT-Link"
    });

    //Virus Total Sanitize Link
    chrome.contextMenus.create({
        "title": 'Sanitize',
        "contexts": ["link"],
        "parentId": "VirusT-Link",
        "id": "VT-Sanitize"
    });
    // Censys Link
    chrome.contextMenus.create({
        "title": 'Search Link On Censys',
        "contexts": ["link"],
        "parentId":"Link",
        "id": "Censys-Link"
    });

    // Censys Sanitize Link
    chrome.contextMenus.create({
        "title": 'Sanitize',
        "contexts": ["link"],
        "parentId":"Censys-Link",
        "id": "C-Sanitize"
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
});
    
chrome.contextMenus.onClicked.addListener(function(info, tab) {
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
            url: "https://www.virustotal.com/gui/domain/" + encodeURIComponent(info.linkUrl)
            });
        }
    }
    // Virus Total Sanitize Link
    if(info.menuItemId == "VT-Sanitize"){
        if(/^(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/.test(info.selectionText)){
            chrome.tabs.create({  
                url: "https://www.virustotal.com/gui/ip-address/" + encodeURIComponent(info.linkUrl.replace(/^(?:https?:\/\/)?(?:[^\/]+\.)?([^.\/]+\.[^.\/]+).*$/, "$1"))
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
    // Talos Sanitize

    if(info.menuItemId == "T-Sanitize"){
        chrome.tabs.create({  
            url: "https://www.talosintelligence.com/reputation_center/lookup?search=" + encodeURIComponent(info.linkUrl.replace(/^(?:https?:\/\/)?(?:[^\/]+\.)?([^.\/]+\.[^.\/]+).*$/, "$1"))
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
            url: "https://search.censys.io/search?resource=hosts&sort=RELEVANCE&per_page=25&virtual_hosts=EXCLUDE&q=" + encodeURIComponent(info.linkUrl)
            });
        }
    }

    if(info.menuItemId == "C-Sanitize"){
        if(/^(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/.test(info.selectionText)){
            chrome.tabs.create({  
                url: "https://search.censys.io/hosts/" + encodeURIComponent(info.linkUrl.replace(/^(?:https?:\/\/)?(?:[^\/]+\.)?([^.\/]+\.[^.\/]+).*$/, "$1"))
            });
        }else{
            chrome.tabs.create({  
            url: "https://search.censys.io/search?resource=hosts&sort=RELEVANCE&per_page=25&virtual_hosts=EXCLUDE&q=" + encodeURIComponent(info.linkUrl.replace(/^(?:https?:\/\/)?(?:[^\/]+\.)?([^.\/]+\.[^.\/]+).*$/, "$1"))
            });
        }
    }


})