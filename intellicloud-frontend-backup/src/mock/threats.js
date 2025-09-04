//File contains mock threats

const mockThreats = [
    {
        id: 1,
        ip: "192.168.1.1",
        threat_level: "High",
        description: "Port scan detected",
        created_at: "2025-07008T12:00:00Z",
    },

    {
        id: 2,
        ip: "10.0.0.5",
        threat_level: "Medium",
        description: "Suspicious login attempt",
        created_at: "2025-07-07T14:30:00z"
    },
];

export default mockThreats;