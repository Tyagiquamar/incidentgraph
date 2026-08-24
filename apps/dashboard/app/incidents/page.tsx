import Link from "next/link";
import { apiGet, type Incident } from "../../lib/api";
import { shortID } from "../../lib/format";

export const dynamic = "force-dynamic";

export default async function IncidentsPage() {
  let incidents: Incident[] = [];
  let error: string | null = null;
  try {
    incidents = await apiGet<Incident[]>("/incidents?limit=50");
  } catch (e) {
    error = e instanceof Error ? e.message : String(e);
  }

  return (
    <>
      <h1>Incidents</h1>
      {error && <div className="error">API unreachable: {error}</div>}
      {!error && (
        <table>
          <thead>
            <tr>
              <th>ID</th>
              <th>Title</th>
              <th>Service</th>
              <th>Severity</th>
            </tr>
          </thead>
          <tbody>
            {incidents.map((inc) => (
              <tr key={inc.id}>
                <td className="mono">
                  <Link href={`/incidents/${inc.id}`}>{shortID(inc.id)}</Link>
                </td>
                <td>
                  <Link href={`/incidents/${inc.id}`}>{inc.title}</Link>
                </td>
                <td>{inc.service}</td>
                <td>{inc.severity}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </>
  );
}
