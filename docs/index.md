import React from 'react';
import Layout from '@theme/Layout';
import Link from '@docusaurus/Link';

export default function Home() {
  return (
    <Layout
      title="Internal Security Knowledge Base"
      description="A field manual for internal pentesting and Active Directory operations"
    >
      {/* HERO */}
      <header
        style={{
          padding: '5rem 1rem',
          textAlign: 'center',
          background: 'linear-gradient(90deg, #020617, #0f172a)',
          color: '#ffffff',
        }}
      >
        <h1 style={{ fontSize: '3rem', marginBottom: '1rem' }}>
          Internal Security Knowledge Base
        </h1>

        <p style={{ fontSize: '1.3rem', opacity: 0.9 }}>
          A field manual for internal pentesting and Active Directory operations
        </p>

        <div style={{ marginTop: '2.5rem' }}>
          <Link
            className="button button--primary button--lg"
            to="/docs/osep/scanning/external-nmap"
          >
            📖 Open Field Manual
          </Link>
        </div>
      </header>

      {/* MAIN CONTENT */}
      <main
        style={{
          padding: '3rem 1rem',
          maxWidth: '900px',
          margin: '0 auto',
        }}
      >
        {/* INTRO */}
        <section style={{ marginBottom: '3rem' }}>
          <p>
            This project serves as a technical field manual for internal security
            work. It documents commands, workflows, and operational observations
            commonly encountered during internal network assessments.
          </p>

          <p>
            The emphasis is on repeatability, speed, and practical execution
            rather than theory or step-by-step tutorials.
          </p>
        </section>

        {/* SCOPE */}
        <section style={{ marginBottom: '3rem' }}>
          <h2>Scope</h2>
          <ul>
            <li>Internal network and service enumeration</li>
            <li>Initial access techniques and delivery mechanisms</li>
            <li>Active Directory reconnaissance and attack paths</li>
            <li>Privilege escalation and lateral movement</li>
            <li>Defense evasion and post-exploitation workflows</li>
            <li>Utilities, payloads, and operational tooling</li>
          </ul>
        </section>

        {/* USAGE */}
        <section style={{ marginBottom: '3rem' }}>
          <h2>How to use this manual</h2>
          <ul>
            <li>Use it as a quick reference during labs or assessments</li>
            <li>Expect concise notes and copy-ready commands</li>
            <li>Assume prior understanding of core security concepts</li>
          </ul>
        </section>

        {/* CONTRIBUTIONS */}
        <section style={{ marginBottom: '3rem' }}>
          <h2>Contributions</h2>
          <p>
            Improvements, corrections, and additional content are welcome.
            If you identify an issue or have a better approach, feel free to
            submit a pull request.
          </p>
        </section>

        {/* DISCLAIMER */}
        <section>
          <h2>Disclaimer</h2>
          <p>
            This content is provided for educational and research purposes only.
            All techniques should be used strictly in authorized and controlled
            environments.
          </p>
        </section>
      </main>
    </Layout>
  );
}
