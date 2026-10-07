import React, { useState, useCallback } from 'react';

export default function LogParserDashboard() {
  const [isDragging, setIsDragging] = useState(false);
  const [loading, setLoading] = useState(false);
  const [results, setResults] = useState(null);
  const [error, setError] = useState(null);
  const [rules, setRules] = useState({ email: true, ssn: true });
  const [showLicenseManager, setShowLicenseManager] = useState(false);
  const [licenseKey, setLicenseKey] = useState(() => localStorage.getItem('saas_license_key') || '');

  // Drag over states

  // Drag over states
  const handleDragOver = useCallback((e) => {
    e.preventDefault();
    setIsDragging(true);
  }, []);

  const handleDragLeave = useCallback((e) => {
    e.preventDefault();
    setIsDragging(false);
  }, []);

  // Post raw file contents directly to local FastAPI engine
  const uploadFile = async (file) => {
    setLoading(true);
    setError(null);
    setResults(null);

    const formData = new FormData();
    formData.append("file", file);
    formData.append("rules", JSON.stringify(rules));

    try {
      const response = await fetch("http://localhost:8000/api/v1/parse", {
        method: "POST",
        headers: {
          "X-SaaS-License-Key": localStorage.getItem('saas_license_key') || '',
        },
        body: formData,
      });

      if (!response.ok) {
        const errorData = await response.json();
        throw new Error(errorData.detail || "Server layout or parsing failure.");
      }

      const data = await response.json();
      setResults(data);
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  // Capture file drop
  const handleDrop = useCallback((e) => {
    e.preventDefault();
    setIsDragging(false);
    
    if (e.dataTransfer.files && e.dataTransfer.files[0]) {
      uploadFile(e.dataTransfer.files[0]);
    }
  }, []);

  // Handle standard click selection
  const handleFileChange = (e) => {
    if (e.target.files && e.target.files[0]) {
      uploadFile(e.target.files[0]);
    }
  };

  // Compute category counts for metrics panel
  const getCategoryMetrics = () => {
    if (!results || !results.data) return {};
    return results.data.reduce((acc, record) => {
      const cat = record.category || 'GENERIC';
      acc[cat] = (acc[cat] || 0) + 1;
      return acc;
    }, {});
  };

  const metrics = getCategoryMetrics();
  const maxCount = Math.max(...Object.values(metrics), 1);

  return (
    <div style={{ maxWidth: '900px', margin: '40px auto', padding: '0 20px', fontFamily: 'sans-serif', color: '#1a1a1a' }}>
      <div style={{ marginBottom: "20px", padding: "15px", backgroundColor: "#f3f4f6", borderRadius: "8px", display: "flex", gap: "20px", fontSize: "14px", alignItems: "center" }}>
        <strong>Rule Filters:</strong>
        {Object.keys(rules).map(rule => (
          <label key={rule} style={{ cursor: "pointer", display: "flex", alignItems: "center", gap: "5px" }}>
            <input 
              type="checkbox" 
              checked={rules[rule]} 
              onChange={() => setRules(prev => ({ ...prev, [rule]: !prev[rule] }))}
            /> {rule.toUpperCase()}
          </label>
        ))}
        <button 
          onClick={() => setShowLicenseManager(!showLicenseManager)}
          style={{ marginLeft: 'auto', padding: '4px 8px', cursor: 'pointer', fontSize: '12px' }}
        >
          {showLicenseManager ? 'Close License Manager' : 'Manage License'}
        </button>
      </div>

      {showLicenseManager && (
        <div style={{ marginBottom: '30px', padding: '20px', backgroundColor: '#fff', border: '1px solid #d1d5db', borderRadius: '8px' }}>
          <h4 style={{ margin: '0 0 10px 0' }}>SaaS License Key</h4>
          <div style={{ display: 'flex', gap: '10px' }}>
            <input 
              type="text" 
              value={licenseKey} 
              onChange={(e) => setLicenseKey(e.target.value)} 
              placeholder="Enter license key..."
              style={{ flex: 1, padding: '8px', borderRadius: '4px', border: '1px solid #d1d5db' }}
            />
            <button 
              onClick={() => { localStorage.setItem('saas_license_key', licenseKey); alert('License saved!'); }}
              style={{ padding: '8px 16px', backgroundColor: '#2563eb', color: '#fff', border: 'none', borderRadius: '4px', cursor: 'pointer' }}
            >
              Save Key
            </button>
          </div>
        </div>
      )}

      <header style={{ marginBottom: "30px" }}>
        <h1 style={{ fontSize: '24px', fontWeight: 'bold' }}>Compliance Normalizer & Sanitizer</h1>
        <p style={{ color: '#666', fontSize: '14px' }}>Deterministic local pipeline for PCI-DSS, HIPAA, and GDPR/SOC2 workflows.</p>
      </header>

      {/* DRAG AND DROP ZONE */}
      <div
        onDragOver={handleDragOver}
        onDragLeave={handleDragLeave}
        onDrop={handleDrop}
        style={{
          border: `2px dashed ${isDragging ? '#2563eb' : '#d1d5db'}`,
          backgroundColor: isDragging ? '#eff6ff' : '#f9fafb',
          borderRadius: '8px',
          padding: '40px 20px',
          textAlign: 'center',
          cursor: 'pointer',
          transition: 'all 0.2s ease',
        }}
      >
        <input
          type="file"
          id="fileUpload"
          style={{ display: 'none' }}
          onChange={handleFileChange}
          accept=".log,.txt,.xml,.json"
        />
        <label htmlFor="fileUpload" style={{ cursor: 'pointer', display: 'block' }}>
          <div style={{ fontSize: '32px', marginBottom: '10px' }}>📁</div>
          <p style={{ margin: '0 0 4px 0', fontWeight: '600' }}>
            {loading ? "Analyzing logs..." : "Drag and drop your raw log files here"}
          </p>
          <p style={{ margin: '0', fontSize: '12px', color: '#6b7280' }}>
            Supports .log, .txt, .xml, .json up to 100MB
          </p>
        </label>
      </div>

      {/* ERROR FEEDBACK BAR */}
      {error && (
        <div style={{ marginTop: '20px', padding: '12px 16px', backgroundColor: '#fef2f2', borderLeft: '4px solid #ef4444', borderRadius: '4px', color: '#991b1b', fontSize: '14px' }}>
          <strong style={{ fontWeight: 'bold' }}>System Interruption:</strong> {error}
        </div>
      )}

      {/* SYSTEM DATA RESULTS VIEW */}
      {results && (
        <div style={{ marginTop: '40px' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '15px' }}>
            <h3 style={{ fontSize: '18px', margin: 0 }}>Normalized Records Summary</h3>
            <span style={{ backgroundColor: '#e0f2fe', color: '#0369a1', padding: '4px 8px', borderRadius: '12px', fontSize: '12px', fontWeight: 'bold' }}>
              Records Processed: {results.total_records}
            </span>
          </div>

          <div style={{ maxHeight: '400px', overflowY: 'auto', border: '1px solid #e5e7eb', borderRadius: '6px' }}>
            <table style={{ width: '100%', borderCollapse: 'collapse', textAlign: 'left', fontSize: '13px' }}>
              <thead style={{ backgroundColor: '#f3f4f6', position: 'sticky', top: 0, zIndex: 1 }}>
                <tr>
                  <th style={{ padding: '10px 12px', borderBottom: '1px solid #e5e7eb' }}>Timestamp</th>
                  <th style={{ padding: '10px 12px', borderBottom: '1px solid #e5e7eb' }}>Level</th>
                  <th style={{ padding: '10px 12px', borderBottom: '1px solid #e5e7eb' }}>Sanitized Message</th>
                </tr>
              </thead>
              <tbody>
                {results.data.map((record, index) => (
                  <tr key={index} style={{ borderBottom: '1px solid #f3f4f6' }}>
                    <td style={{ padding: '10px 12px', fontFamily: 'monospace', color: '#4b5563' }}>{record.timestamp}</td>
                    <td style={{ padding: '10px 12px' }}>
                      <span style={{
                        padding: '2px 6px',
                        borderRadius: '4px',
                        fontSize: '11px',
                        fontWeight: 'bold',
                        color: record.level === 'ERROR' || record.level === 'CRITICAL' ? '#991b1b' : '#1e2838',
                        backgroundColor: record.level === 'ERROR' || record.level === 'CRITICAL' ? '#fef2f2' : '#f1f5f9'
                      }}>
                        {record.level}
                      </span>
                    </td>
                    <td style={{ padding: '10px 12px', color: '#111827' }}>{record.message}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  );
}
