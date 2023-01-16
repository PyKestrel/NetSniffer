document.getElementById("customPortsSelector").addEventListener('change', function(){
    if(this.checked){
        document.getElementById("customPorts").style.display = "inline";
        document.getElementById("defaultPortsSelector").setAttribute("disabled", "disabled");
    }else{
        document.getElementById("customPorts").style.display = "none";
        document.getElementById("defaultPortsSelector").removeAttribute("disabled");
    }
});
document.getElementById("defaultPortsSelector").addEventListener('change', function(){
    if(this.checked){
        document.getElementById("customPortsSelector").setAttribute("disabled", "disabled");
    }else{
        document.getElementById("customPortsSelector").removeAttribute("disabled");
    }
});


function portScan(){
    Results = document.getElementById("results");
    Results.innerHTML = "";
    console.log("Scan Initializing");
    Results.innerHTML += "Scan Initializing<br>";

    Results.innerHTML += "Creating Abort Controller<br>";
    // Controls Connection Timeouts
    var controller = new AbortController();
    var signal = controller.signal;
    setTimeout(() => {controller.abort();}, 5000);

    Results.innerHTML += "Created Abort Controller<br>";
    
    var default_ports = [ 1,5,7,9,15,20,21,22,23,25,26,29,33,37,42,43,53,67,68,69,70,76,79,80,88,90,98,101,106,109,110,111,113,114,115,118,119,123,129,132,133,135,136,137,138,139,143,144,156,158,161,162,168,174,177,194,197,209,213,217,219,220,223,264,315,316,346,353,389,413,414,415,416,440,443,444,445,453,454,456,457,458,462,464,465,466,480,486,497,500,501,516,518,522,523,524,525,526,533,535,538,540,541,542,543,544,545,546,547,556,557,560,561,563,564,625,626,631,636,637,660,664,666,683,740,741,742,744,747,748,749,750,751,752,753,754,758,760,761,762,763,764,765,767,771,773,774,775,776,780,781,782,783,786,787,799,800,801,808,871,873,888,898,901,953,989,990,992,993,994,995,996,997,998,999,1000,1002,1008,1023,1024,1080,8080,8443,8050,3306,5432,1521,1433,3389,10088 ];

    let host = document.getElementById("hostname").value;

    // GUI Stuff
    Results.innerHTML += "Starting Scan" + "<br>";
    Results.innerHTML += "<tr> <th>Port</th><th>Determination</th><th>Return Code</th><th>Return Message</th><tr>";
    if(document.getElementById("defaultPortsSelector").checked){
        for (let index = 0; index < default_ports.length; index++) {
            let port = default_ports[index];
            fetch('https://'+host+':'+port,{
                method: 'GET',
                mode: 'no-cors',
                signal: signal,
            })
            .then((response) =>
                response
            )
            .then((data) => {
                // Succesful Connection, Most Likely A 443 Port As We're Using HTTPS, But Any Port Running HTTPS Should Return Succesful. Even If The Status Maybe Something Other Than 200.
                console.log("Port "+port+"  open"+"  Return Code: " + data.status + "Server Type: " + data.headers.get("server"));
                Results.innerHTML += "Port "+port+"  open"+"  Return Code: " + data.status + "Server Type: " + data.headers.get("server") +"<br>";
            }).catch(err => {
                // If Connection Is Aborted Then Its Because By Default After 5 Seconds The Connection Attempt Is Aborted And More Than Likely The Port Is Closed Or Filtered
                if(signal.aborted === true || err.code == 20){
                    console.log("Port "+port+"  closed/filtered");
                    Results.innerHTML += "<tr><td>"+port+"</td><td>closed/filtered</td></tr>";
                }
                // If We Receive An EPROTO Error Then The Port Is Open, We're Just Using An Incompatible Protocol i.e HTTPS.
                // If We Receive An ECONNREFUSED Error Then The Port Is Open, The Server Is Simply Resetting Our Connection.
                else if(err.code == "EPROTO" || err.code == "ECONNREFUSED" || err.message == "Failed to fetch"){
                    console.log("Port "+port+"  open(?)     "+"      Return Code: " + err.code + "         Return Message: " + err.message);
                    Results.innerHTML += "<tr> <td>"+port+"</td>  <td>open(?)</td>"+"<td>" + err.code + "</td> <td>" + err.message + "</td><tr>";
                }
            });
        }
    }
    else if(document.getElementById("customPortsSelector").checked){
        //Parse Custom Ports
        var customPortsRAW = document.getElementById("customPorts").value.trim().split(",");
        let portsToScan = [];
        customPortsRAW.forEach(elm =>{
            // Parse Ranges
            if(elm.includes("-")){
                let range = elm.split("-");
                // Convert Strings To Integers
                for (let index = Number(range[0]); index <= Number(range[1]); index++) {
                    // Push Parsed Range To An Array That Will Be Used To Scan Later
                    portsToScan.push(index.toString());
                }
            }else{
                // Push Custom Port To Array To Be Scanned Later
                portsToScan.push(elm);
            }
        })
        for (let index = 0; index < portsToScan.length; index++) {
            let port = portsToScan[index];
            fetch('https://'+host+':'+port,{
                method: 'GET',
                mode: 'no-cors',
                signal: signal,
            })
            .then((response) =>
                response
            )
            .then((data) => {
                // Succesful Connection, Most Likely A 443 Port As We're Using HTTPS, But Any Port Running HTTPS Should Return Succesful. Even If The Status Maybe Something Other Than 200.
                console.log("Port "+port+"  open"+"  Return Code: " + data.status + "Server Type: " + data.headers.get("server"));
                Results.innerHTML += "Port "+port+"  open"+"  Return Code: " + data.status + "Server Type: " + data.headers.get("server") +"<br>";
            }).catch(err => {
                // If Connection Is Aborted Then Its Because By Default After 5 Seconds The Connection Attempt Is Aborted And More Than Likely The Port Is Closed Or Filtered
                if(signal.aborted === true || err.code == 20){
                    console.log("Port "+port+"  closed/filtered");
                    Results.innerHTML += "<tr><td>"+port+"</td><td>closed/filtered</td></tr>";
                }
                // If We Receive An EPROTO Error Then The Port Is Open, We're Just Using An Incompatible Protocol i.e HTTPS.
                // If We Receive An ECONNREFUSED Error Then The Port Is Open, The Server Is Simply Resetting Our Connection.
                else if(err.code == "EPROTO" || err.code == "ECONNREFUSED" || err.message == "Failed to fetch"){
                    console.log("Port "+port+"  open(?)     "+"      Return Code: " + err.code + "         Return Message: " + err.message);
                    Results.innerHTML += "<tr> <td>"+port+"</td>  <td>open(?)</td>"+"<td>" + err.code + "</td> <td>" + err.message + "</td><tr>";
                }
            });
        }
    }
    else{
        console.log("An Err Occurred");
    }
}

document.getElementById("scanButton").addEventListener("click", portScan);