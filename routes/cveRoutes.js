const express = require('express');
const { fetchCves, fetchCveById } = require('../controllers/cveController');

const router = express.Router();

// Route for listing CVEs
router.get('/cve-detail/:cveId', async (req, res) => {
  const { cveId } = req.params;
  try {
    console.log(cveId);
    const cveDetails = await fetchCveById(cveId);

    if (cveDetails) {
      const { descriptions, metrics, references, weaknesses, configurations } = cveDetails;
      const { cvssMetricV2 } = metrics;

      const descriptionList = descriptions
        .map((desc) => `<li>${desc.value}</li>`)
        .join('');

      const {
        baseScore,
        vectorString,
        baseSeverity,
        accessVector,
        accessComplexity,
        authentication,
        confidentialityImpact,
        integrityImpact,
        availabilityImpact,
      } = cvssMetricV2[0].cvssData;

      const exploitabilityScore = cvssMetricV2[0].exploitabilityScore;
      const impactScore = cvssMetricV2[0].impactScore;

      const cpeTableRows = configurations
        .map(config =>
          config.nodes.map(node =>
            node.cpeMatch.map(cpe =>
              `<tr>
                <td>${cpe.criteria}</td>
                <td>${cpe.matchCriteriaId}</td>
                <td>${cpe.vulnerable}</td>
              </tr>`
            ).join('')
          ).join('')
        ).join('');

      res.send(`
        <!DOCTYPE html>
        <html lang="en">
        <head>
          <meta charset="UTF-8">
          <meta name="viewport" content="width=device-width, initial-scale=1.0">
          <title>${cveId} Details</title>
          <style>
            body {
              font-family: Arial, sans-serif;
              margin: 0;
              padding: 20px;
              color: #333;
            }
            h1, h3 {
              text-align: center;
              color: #2c3e50;
            }
            .section {
              margin: 30px auto;
              width: 80%;
            }
            .highlight {
              background-color: #f9f9f9;
              border: 1px solid #ddd;
              padding: 15px;
              margin: 20px auto;
              width: 80%;
              text-align: center;
              border-radius: 5px;
              box-shadow: 0 2px 5px rgba(0, 0, 0, 0.1);
            }
            table {
              width: 80%;
              margin: 20px auto;
              border-collapse: collapse;
            }
            table th, table td {
              border: 1px solid #ddd;
              padding: 10px;
              text-align: center;
            }
            table th {
              background-color: #f4f4f4;
              color: #333;
            }
            ul {
              list-style: none;
              padding-left: 0;
            }
            li {
              margin: 5px 0;
            }
            a {
              color: #3498db;
              text-decoration: none;
            }
            a:hover {
              text-decoration: underline;
            }
          </style>
        </head>
        <body>
          <h1>CVE-Details: ${cveId}</h1>
          
          <!-- Descriptions -->
          <div class="section">
            <h3>Description</h3>
            <ul>${descriptionList || '<li>No description available.</li>'}</ul>
          </div>

          <!-- Highlighted CVSS V2 Metrics -->
          <div class="highlight">
            <h3>Severity: ${baseSeverity}</h3>
            <p><strong>Score:</strong> ${baseScore}</p>
            <p><strong>Vector String:</strong> ${vectorString}</p>
            <p><strong>Exploitability Score:</strong> ${exploitabilityScore}</p>
            <p><strong>Impact Score:</strong> ${impactScore}</p>
          </div>

          <!-- Other CVSS Details -->
          <div class="section">
            <h3>Additional CVSS V2 Details</h3>
            <table>
              <tr>
                <th>Access Vector</th>
                <th>Access Complexity</th>
                <th>Authentication</th>
                <th>Confidentiality Impact</th>
                <th>Integrity Impact</th>
                <th>Availability Impact</th>
              </tr>
              <tr>
                <td>${accessVector}</td>
                <td>${accessComplexity}</td>
                <td>${authentication}</td>
                <td>${confidentialityImpact}</td>
                <td>${integrityImpact}</td>
                <td>${availabilityImpact}</td>
              </tr>
            </table>
          </div>

          <!-- CPE Table -->
          <div class="section">
            <h3>Configurations (CPE Data)</h3>
            <table>
              <tr>
                <th>Criteria</th>
                <th>Match Criteria ID</th>
                <th>Vulnerable</th>
              </tr>
              ${cpeTableRows || '<tr><td colspan="3">No CPE data available.</td></tr>'}
            </table>
          </div>

          <!-- References -->
          <div class="section">
            <h3>References</h3>
            <ul>
              ${references.map(ref => `<li><a href="${ref.url}" target="_blank">${ref.url}</a></li>`).join('')}
            </ul>
          </div>

          <!-- Weaknesses -->
          <div class="section">
            <h3>Weaknesses</h3>
            <ul>
              ${weaknesses.map(weakness => `<li>${weakness.description[0].value}</li>`).join('')}
            </ul>
          </div>
        </body>
        </html>
      `);
    } else {
      res.status(404).send({ message: 'CVE not found' });
    }
  } catch (error) {
    console.error('Error fetching CVE details:', error);
    res.status(500).json({ message: 'Failed to fetch CVE details' });
  }
});

// Route to fetch CVEs with pagination
router.get('/list', async (req, res) => {
  const resultsPerPage = parseInt(req.query.resultsPerPage) || 10;
  const page = parseInt(req.query.page) || 1;
  const searchCveId = req.query.searchCveId || '';
  const startDate = req.query.startDate || '';
  // const endDate = req.query.endDate || '';
  const cvssScore = parseFloat(req.query.cvssScore) || 0;
  

  try {
      const cves = await fetchCves(resultsPerPage, page, searchCveId, startDate, cvssScore);
      // console.log(cvssScore)
      res.json({ vulnerabilities: cves });
  } catch (error) {
      console.error('Error in /list route:', error.message);
      res.status(500).json({ error: 'Failed to fetch CVE data' });
  }
});

module.exports = router;
