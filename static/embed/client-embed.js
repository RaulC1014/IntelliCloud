(function () {
    const scriptTag = document.currentScript;
    const clientApiKey = scriptTag.getAttribute("data-api-key");

    if (!clientApiKey) {
        console.error("IntelliCloud: Missing data-api-key attribute.");
        return;
    }

    fetch ("https://api64.ipify.org?format=json")
    .then((res) => res.json())
    .then((data) => {
        const ip = data.ip;

        return fetch("http://localhost:5000/api/track", {
            method: "POST",
            headers: {
                "Content-Type": "application/json",
            },
            body: JSON.stringify({
                ip: ip,
                clientApiKey: clientApiKey,
            }),
        });
    })

    .then((res) => res.json())
    .then((result) => {
        console.log("IntelliCloud tracking success:", result);
    })
    .catch((err) => {
        console.error("IntelliCloud tracking failed:", err);
    });
    
})();