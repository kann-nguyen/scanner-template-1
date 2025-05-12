import express from "express";
import { spawn } from "child_process";
import { randomUUID } from "crypto";
import "dotenv/config";
import { mkdir, readFile, unlink } from "fs/promises";
import axios from "axios";

const app = express();
const port = 3000;

// Add middleware to parse JSON in query params
app.use((req, res, next) => {
  if (req.query.artifact) {
    try {
      req.query.artifact = JSON.parse(decodeURIComponent(req.query.artifact));
    } catch (error) {
      return res.status(400).json({ error: "Invalid artifact format" });
    }
  }
  next();
});

function log(message, type = "INFO") {
  console.log(`[${new Date().toISOString()}] [${type}] ${message}`);
}

// CVE Information Service - fetches complete vulnerability data from various APIs
class CveInfoService {
  // API URLs
  static APIs = {
    // CircleCi provides a CVE lookup service - no API key required
    circleCI: "https://cve.circl.lu/api/cve/",
    
    // NIST NVD API - rate limited but official data
    nvd: "https://services.nvd.nist.gov/rest/json/cves/2.0",
  };

  // Rate limiting and circuit breaker state
  static rateLimiters = {
    circleCI: { lastRequest: 0, minInterval: 6000 },  // 10 req/min (with buffer)
    nvd: { lastRequest: 0, minInterval: 6000 },       // 10 req/min (with buffer)
  };

  static async getCveInfo(cveId) {
    try {
      log(`Fetching information for ${cveId}`);

      // Try NVD API if CircleCi didn't return data
      // We try this even without an API key, but it might fail with rate limits
      const nvdData = await this.fetchFromNvd(cveId);
      if (nvdData) {
        log(`Retrieved ${cveId} data from NVD API`);
        return {
          score: this.extractScoreFromNvd(nvdData),
          cvssVector: this.extractVectorFromNvd(nvdData),
          cwes: this.extractCwesFromNvd(nvdData)
        };
      }

      // Try CircleCi first - generally reliable and no authentication needed
      const circleData = await this.fetchFromCircleCi(cveId);
      if (circleData) {
        log(`Retrieved ${cveId} data from CircleCi API`);
        return {
          score: this.extractScoreFromCircleCi(circleData),
          cvssVector: this.extractVectorFromCircleCi(circleData),
          cwes: this.extractCwesFromCircleCi(circleData)
        };
      }

      log(`Could not find data for ${cveId} in any API`, "WARN");
      return null;

    } catch (error) {
      log(`Error fetching CVE info: ${error.message}`, "ERROR");
      return null;
    }
  }

  // Throttle requests to respect API rate limits
  static async throttleRequest(api) {
    const now = Date.now();
    const limiter = this.rateLimiters[api];
    
    if (!limiter) return;
    
    const elapsed = now - limiter.lastRequest;
    if (elapsed < limiter.minInterval) {
      const delay = limiter.minInterval - elapsed;
      await new Promise(resolve => setTimeout(resolve, delay));
    }
    
    this.rateLimiters[api].lastRequest = Date.now();
  }

  // CircleCi API methods
  static async fetchFromCircleCi(cveId) {
    try {
      await this.throttleRequest('circleCI');
      const response = await axios.get(`${this.APIs.circleCI}${cveId}`, {
        timeout: 5000
      });
      
      if (response.status === 200 && response.data) {
        return response.data;
      }
      return null;
    } catch (error) {
      log(`CircleCi fetch error for ${cveId}: ${error.message}`, "WARN");
      return null;
    }
  }

  static extractScoreFromCircleCi(data) {
    try {
      // Try to get CVSS3 score first, fall back to CVSS2
      if (data.cvss3) {
        return parseFloat(data.cvss3);
      } else if (data.cvss) {
        return parseFloat(data.cvss);
      }
      return null;
    } catch (error) {
      return null;
    }
  }

  static extractVectorFromCircleCi(data) {
    try {
      // Try to get CVSS3 vector first, fall back to CVSS2
      if (data.cvss3_vector) {
        return data.cvss3_vector;
      } else if (data.cvss_vector) {
        return data.cvss_vector;
      }
      return null;
    } catch (error) {
      return null;
    }
  }

  static extractCwesFromCircleCi(data) {
    try {
      const cwes = [];
      
      // CircleCi API sometimes includes CWEs in references
      if (data.references) {
        for (const ref of data.references) {
          if (ref.toLowerCase().includes('cwe-')) {
            // Extract CWE-XXX pattern
            const match = ref.match(/CWE-\d+/i);
            if (match) cwes.push(match[0]);
          }
        }
      }

      // CircleCi may also have CWEs in capec field
      if (data.capec && Array.isArray(data.capec)) {
        for (const capec of data.capec) {
          if (capec.related_weakness && Array.isArray(capec.related_weakness)) {
            for (const cwe of capec.related_weakness) {
              if (cwe) cwes.push(`CWE-${cwe}`);
            }
          }
        }
      }

      return cwes.length > 0 ? cwes : null;
    } catch (error) {
      return null;
    }
  }

  // NVD API methods
  static async fetchFromNvd(cveId) {
    try {
      await this.throttleRequest('nvd');

      // Check if NVD API key is available (recommended for production)
      const headers = {};
      const nvd_token = `95d40afa-9118-4d88-bd1e-9e1c15d4c91d`;
      headers['apiKey'] = nvd_token;
      if (process.env.NVD_API_KEY) {
        headers['apiKey'] = process.env.NVD_API_KEY;
      }

      const response = await axios.get(this.APIs.nvd, {
        params: { cveId },
        headers,
        timeout: 10000
      });

      if (response.status === 200 && 
          response.data && 
          response.data.vulnerabilities && 
          response.data.vulnerabilities.length > 0) {
        return response.data.vulnerabilities[0].cve;
      }
      return null;
    } catch (error) {
      log(`NVD fetch error for ${cveId}: ${error.message}`, "WARN");
      return null;
    }
  }

  static extractScoreFromNvd(data) {
    try {
      if (!data.metrics) return null;

      // Try CVSS 3.1 first, then 3.0, then 2.0
      if (data.metrics.cvssMetricV31 && data.metrics.cvssMetricV31.length > 0) {
        return data.metrics.cvssMetricV31[0].cvssData.baseScore;
      } else if (data.metrics.cvssMetricV30 && data.metrics.cvssMetricV30.length > 0) {
        return data.metrics.cvssMetricV30[0].cvssData.baseScore;
      } else if (data.metrics.cvssMetricV2 && data.metrics.cvssMetricV2.length > 0) {
        return data.metrics.cvssMetricV2[0].cvssData.baseScore;
      }
      return null;
    } catch (error) {
      return null;
    }
  }

  static extractVectorFromNvd(data) {
    try {
      if (!data.metrics) return null;

      // Try CVSS 3.1 first, then 3.0, then 2.0
      if (data.metrics.cvssMetricV31 && data.metrics.cvssMetricV31.length > 0) {
        return data.metrics.cvssMetricV31[0].cvssData.vectorString;
      } else if (data.metrics.cvssMetricV30 && data.metrics.cvssMetricV30.length > 0) {
        return data.metrics.cvssMetricV30[0].cvssData.vectorString;
      } else if (data.metrics.cvssMetricV2 && data.metrics.cvssMetricV2.length > 0) {
        return data.metrics.cvssMetricV2[0].cvssData.vectorString;
      }
      return null;
    } catch (error) {
      return null;
    }
  }

  static extractCwesFromNvd(data) {
    try {
      const cwes = [];
      
      if (data.weaknesses && Array.isArray(data.weaknesses)) {
        for (const weakness of data.weaknesses) {
          if (weakness.description && Array.isArray(weakness.description)) {
            for (const desc of weakness.description) {
              if (desc.value && desc.value.startsWith('CWE-')) {
                cwes.push(desc.value);
              }
            }
          }
        }
      }
      
      return cwes.length > 0 ? cwes : null;
    } catch (error) {
      return null;
    }
  }
}

// Function to capture statistics about vulnerability data completeness
function getVulnerabilityStats(vulnerabilities) {
  const total = vulnerabilities.length;
  const withScore = vulnerabilities.filter(v => v.score !== null).length;
  const withVector = vulnerabilities.filter(v => v.cvssVector !== null).length;
  const withCwes = vulnerabilities.filter(v => v.cwes !== null && v.cwes.length > 0).length;
  const complete = vulnerabilities.filter(v => 
    v.score !== null && 
    v.cvssVector !== null && 
    v.cwes !== null && 
    v.cwes.length > 0
  ).length;
  
  const stats = {
    totalVulnerabilities: total,
    withScore,
    withVector,
    withCwes,
    complete,
    scorePercentage: total > 0 ? Math.round((withScore / total) * 100) : 0,
    vectorPercentage: total > 0 ? Math.round((withVector / total) * 100) : 0,
    cwesPercentage: total > 0 ? Math.round((withCwes / total) * 100) : 0,
    completePercentage: total > 0 ? Math.round((complete / total) * 100) : 0
  };
    return stats;
}

// Extract basic vulnerability data from Grype scan and enrich with external API data if needed
async function processVulnerability(vulnerability) {
  const { id, severity, description } = vulnerability;
  
  // Try to get data from Grype first
  let cvssScore = null;
  let cvssVector = null;
  let cwes = [];

  if (vulnerability.cvss && vulnerability.cvss.length > 0) {
    const latestCvss = vulnerability.cvss[vulnerability.cvss.length - 1];
    cvssScore = latestCvss?.metrics?.baseScore;
    cvssVector = latestCvss?.vector;
  }
  
  // Extract CWEs from Grype if available
  if (vulnerability.cwe && Array.isArray(vulnerability.cwe)) {
    cwes = [...vulnerability.cwe];
  } else if (vulnerability.related && Array.isArray(vulnerability.related.cwes)) {
    cwes = [...vulnerability.related.cwes];
  } else if (vulnerability.dataSource && vulnerability.dataSource.cwe) {
    if (Array.isArray(vulnerability.dataSource.cwe)) {
      cwes = [...vulnerability.dataSource.cwe];
    } else {
      cwes = [vulnerability.dataSource.cwe];
    }
  }
  
  // If we're missing any data, try to get it from external APIs
  if (!cvssScore || !cvssVector || cwes.length === 0) {
    const externalData = await CveInfoService.getCveInfo(id);
    if (externalData) {
      // Only use external data if we don't have it from Grype
      if (!cvssScore && externalData.score) cvssScore = externalData.score;
      if (!cvssVector && externalData.cvssVector) cvssVector = externalData.cvssVector;
      if (cwes.length === 0 && externalData.cwes) cwes = externalData.cwes;
    }
  }
  
  return {
    cveId: id,
    severity,
    description,
    score: cvssScore,
    cvssVector: cvssVector,
    cwes: cwes.length > 0 ? cwes : null,
  };
}

// Determine security state based on vulnerability severity levels
function determineSecurityState(vulnerabilities) {
  const criticals = vulnerabilities.filter((v) => v.severity === "Critical");
  const highs = vulnerabilities.filter((v) => v.severity === "High");

  let securityState = "S6";
  if (criticals.length === 0 && highs.length === 0) {
    securityState = "S3";
  } else if (criticals.length > 0) {
    securityState = "S5.2";
  } else if (highs.length > 0) {
    securityState = "S5.1*";
  }
  
  return securityState;
}

<code_placeholder>

app.get("/scan", async (req, res) => {
  try {
    const { name } = req.query;
    if (!name) {
      return res.status(400).json({ error: "Missing image name" });
    }

    const result = await processImageScan(name);
    if (result.success) {
      res.json({ 
        message: `Scanning artifact ${name}...`, 
        requestId: result.requestId 
      });
    } else {
      res.status(500).json({ error: result.error, requestId: result.requestId });
    }
  } catch (error) {
    log(`Error processing request: ${error.message}`, "ERROR");
    res.status(500).json({ error: "Internal server error" });
  }
});

app.get("/", (req, res) => {
  res.send("Hello World!");
});

app.listen(port, () => {
  log(`Image scanning service running on port ${port}`);
});