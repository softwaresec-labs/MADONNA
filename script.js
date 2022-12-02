async function fetchData(current_url) {
	revised_url = current_url.replaceAll("/", "_**_");
    const res=await fetch ("http://127.0.0.1:5000/test_url/"+revised_url);
    const record=await res.json();
	
	document.getElementById("checking").style.display="block"
	document.getElementById("benign").style.display="none"
	document.getElementById("checking").style.display="none"
	
	if (record.mal_status == 1){
		document.getElementById("checking").style.display="none"
		document.getElementById("malicious").style.display="block"
		document.getElementById("benign").style.display="none"
	}
	else {
		document.getElementById("checking").style.display="none"
		document.getElementById("benign").style.display="block";
		document.getElementById("malicious").style.display="none";
	}

	
	
	
}

chrome.tabs.query({
    active: true,
    lastFocusedWindow: true
}, function(tabs) {
    var tabURL = tabs[0].url;
	fetchData(tabURL)
    address =tabURL;
});

