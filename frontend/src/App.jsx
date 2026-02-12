import { useState } from 'react'
import './App.css'

function App() {
    const [result, setResult] = useState(null)

    const handleScan = async () => {
        try {
            const response = await fetch('/api/scan', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({
                    subject: 'Test',
                    body: 'Hello'
                })
            })

            const data = await response.json()
            setResult(data)
        } catch (error) {
            console.error("Error:", error)
        }
    }

    return (
        <div style={{ padding: 20 }}>
            <h1>Email Firewall</h1>

            <button onClick={handleScan}>
                Scan Email
            </button>

            {result && (
                <pre>{JSON.stringify(result, null, 2)}</pre>
            )}
        </div>
    )
}

export default App