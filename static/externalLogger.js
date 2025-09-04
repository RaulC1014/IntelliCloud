(async function () {
    
    const apiKey = "<REPLACE_WITH_CLIENT_API_KEY>";

    try {
        const res = await fetch("https://api.ipfy.org?format=json");
        const data = await res.json();
        const ip = data.ip;

        await fetch ("http://localhost:5000/external-log", {
            method: "POST",
            headers: {
                "Content-Type": "application/json",
                "Authroization": `Bearer ${apiKey}`
            },
            body: JSON.stringify({
                ip: ip,
                threat_level: 1
            })
        });
    } catch (err) {
        console.error("IntelliCloud logging failed", err);
    }
})();