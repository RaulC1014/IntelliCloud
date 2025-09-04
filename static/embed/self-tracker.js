(function () {
    const apiKey = document.currentScript.getAttribute("data-api-key");
    if (!apiKey) {
        console.warn ("IntelliCloud: Missing data-api-key");
        return;
    }

    fetch ("https://api64.ipfy.org?format=json")
    .then(res => res.json())
    .then (data => {
        const ip = data.ip;
        return fetch("https://yourdomain.com/api/threats/external-log", {
            method: "POST",
            headers: {
                "Content-Type": "application/json",
                "Authorization": `Bearer ${apiKey}`
            },
            body: JSON.stringify({
                ip: ip,
                threat_level: "low"
            })
        });
    })
    .then (response => {
        if (!response.ok) {
            console.warn("IntelliCloud logging failed:", response.status);
        }
    })
    .catch(err => {
        console.error("IntelliCloud error:", err);
    });
})();
