// Privacy Policy and Terms & Conditions. Text describes what the current software does.
// Anything the project owner must decide or verify is marked CONFIRM and highlighted.
import type { ReactNode } from "react";

const Confirm = ({ children }: { children: ReactNode }) => <mark className="confirm">CONFIRM: {children}</mark>;

function Legal({ title, children }: { title: string; children: ReactNode }) {
  return (
    <article className="legal">
      <div className="notice" role="note">
        <strong>Draft for review.</strong> Highlighted <mark className="confirm">CONFIRM</mark> items need the project
        owner&apos;s input before this page is published, and the whole page should be checked by a qualified person. This
        text describes what the current NetSpectre software does. It is not legal advice.
      </div>
      <h2>{title}</h2>
      <p className="muted">
        Last updated: <Confirm>set the publication date</Confirm>
      </p>
      {children}
    </article>
  );
}

export function PrivacyPage() {
  return (
    <Legal title="Privacy Policy">
      <h3>1. Who this covers</h3>
      <p>
        NetSpectre is open-source software for detecting suspicious activity on a network. It runs on a machine that you
        control, such as a laptop or a Raspberry Pi. This policy explains what the software collects and where that data
        goes. The operator of this installation is{" "}
        <Confirm>name of the person or organisation operating this deployment, and a contact email</Confirm>.
      </p>

      <h3>2. What the monitor observes</h3>
      <p>
        The monitor captures network traffic on the interface it is configured to use. It groups packets into flows and
        calculates 35 numeric features for each flow, such as duration, packet counts, packet sizes, timing and TCP window
        sizes. These features are sent to the machine learning service on the same machine for classification.{" "}
        <Confirm>
          verify against the final build that packet payload contents (web pages, messages, passwords) are never stored or
          logged
        </Confirm>
        .
      </p>

      <h3>3. What is stored</h3>
      <ul>
        <li>
          <strong>Alerts:</strong> time, source IP address, attack label, number of flows, confidence, review status
          (new, acknowledged or dismissed) and a short explanation of why the alert was raised.
        </li>
        <li>
          <strong>Device inventory:</strong> each IP address the monitor has seen, when it was first and last seen, and
          how many flows and alerts it has.
        </li>
      </ul>
      <p>
        IP addresses can identify a person or a household, so treat this data as personal data. It is stored in a SQLite
        database in the monitor&apos;s data folder on the host machine.
      </p>

      <h3>4. Who can see it</h3>
      <p>
        The dashboard and the API are served by the monitor. Requests from the monitor machine itself are allowed.
        Requests from other devices need the API token configured for that installation. This dashboard sets no cookies,
        loads no analytics and loads no third-party scripts or fonts.{" "}
        <Confirm>re-check this statement against the final build and hosting setup</Confirm>.
      </p>

      <h3>5. Optional phone notifications</h3>
      <p>
        Notifications are off unless a notification topic is configured. When on, each notification sends the attack type,
        severity, source IP address, flow count and confidence to the configured ntfy server. The default is the public
        server at ntfy.sh, which is run by a third party and can read that text. Use your own ntfy server to keep alerts
        off third-party systems.
      </p>

      <h3>6. How long data is kept</h3>
      <p>
        The software does not delete alerts or device records automatically. They stay until the database file is removed.{" "}
        <Confirm>state the retention period you commit to, and add automatic deletion if you promise one</Confirm>.
      </p>

      <h3>7. Your choices</h3>
      <ul>
        <li>Export all alerts as CSV from the Reports page.</li>
        <li>Stop monitoring at any time by stopping the monitor container.</li>
        <li>Delete all stored data by removing the database file in the data folder.</li>
        <li>
          To ask the operator about data that concerns you, write to <Confirm>contact email</Confirm>.
        </li>
      </ul>

      <h3>8. Security</h3>
      <p>
        By default the dashboard is served over plain HTTP, which is only suitable on a trusted local network. If this
        installation is reachable through a custom domain or the internet, it must be placed behind HTTPS.{" "}
        <Confirm>describe the final hosting and HTTPS setup</Confirm>. No system is completely secure, and detection results
        can be wrong.
      </p>

      <h3>9. Law and jurisdiction</h3>
      <p>
        <Confirm>
          name the governing law and any data protection rules that apply to this deployment (the project is developed in
          India, where the Digital Personal Data Protection Act, 2023 may apply)
        </Confirm>
        . NetSpectre makes no claim of certification or legal compliance.
      </p>

      <h3>10. Changes</h3>
      <p>This policy may change as the software changes. The date at the top shows the latest revision.</p>
    </Legal>
  );
}

export function TermsPage() {
  return (
    <Legal title="Terms & Conditions">
      <h3>1. About NetSpectre</h3>
      <p>
        NetSpectre is a network intrusion detection project{" "}
        <Confirm>say whether to describe it as an academic final-year project, and name the institution if you wish</Confirm>
        . By using this dashboard you agree to these terms.
      </p>

      <h3>2. Monitor only networks you are allowed to monitor</h3>
      <p>
        Capturing and analysing network traffic can be regulated or illegal without permission. Use NetSpectre only on
        networks that you own or administer, or where you have clear permission from the owner and from the people using
        the network. You are responsible for following the laws that apply to you.
      </p>

      <h3>3. Detection is not a guarantee</h3>
      <p>
        Alerts are predictions made by machine learning models. They can be wrong: real attacks can be missed and normal
        traffic can raise alerts. The measured accuracy in the project documents comes from a public research dataset and
        will differ on a real network. Do not rely on NetSpectre as your only protection, and do not treat an alert as proof
        that a particular device or person did something wrong.
      </p>

      <h3>4. Acceptable use</h3>
      <p>
        You may not use NetSpectre or this dashboard to attack, probe or disrupt any system, to monitor people unlawfully,
        or to interfere with the operation of the service.
      </p>

      <h3>5. Software license</h3>
      <p>
        The NetSpectre source code is published under the MIT License. The license text in the project repository governs
        use of the code.
      </p>

      <h3>6. No warranty and limit of liability</h3>
      <p>
        The software and this dashboard are provided as they are, without warranties of any kind, to the extent the law
        allows. To the same extent, the authors are not liable for losses that result from using them or from relying on
        their alerts. <Confirm>have a qualified person review this clause for your jurisdiction</Confirm>.
      </p>

      <h3>7. Your data</h3>
      <p>How data is handled is described in the Privacy Policy.</p>

      <h3>8. Changes, governing law and contact</h3>
      <p>
        These terms may change, and the date at the top shows the latest revision. Governing law and place of dispute
        resolution: <Confirm>jurisdiction</Confirm>. Contact: <Confirm>contact email</Confirm>.
      </p>
    </Legal>
  );
}
