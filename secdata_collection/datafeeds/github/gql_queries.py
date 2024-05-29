"""github/gql_queries.py

Author: neo154
Version: 0.1.0
Date Modified: 2024-02-06

This is just a spot to keep the simple GQL queries for GITHUB API requests in order to keep them
sorted and separate for cleanlieness in the API connection section
"""

GHSA_CWE_GQL = """query($first: Int, $after: String, $cweFirst: Int, $cweAfter: String){
  securityAdvisories(first: $first, after: $after){
    nodes {
      ghsaId
      cwes(first: $cweFirst, after: $cweAfter){
        nodes {
          cweId
          description
          id
          name
        }
        pageInfo{
          startCursor
          endCursor
          hasNextPage
        }
        totalCount
      }
    }
    pageInfo {
      endCursor
      hasNextPage
    }
    totalCount
  }
}"""

GHSA_GQL = """query($first: Int, $after: String){
  securityAdvisories(first: $first, after: $after){
    nodes {
      ghsaId
      origin
      publishedAt
      description
      severity
      summary
      updatedAt
      classification
      cvss {
        score
        vectorString
      }
      identifiers{
        type
        value
      }
    }
    pageInfo {
      endCursor
      hasNextPage
    }
    totalCount
  }
}"""

GH_VULN_GQL = """query($first: Int, $after: String){
	securityVulnerabilities(first: $first, after: $after) {
    pageInfo {
      endCursor
      hasNextPage
    }
    totalCount
    nodes {
      advisory {
        ghsaId
      }
      firstPatchedVersion {
        identifier
      }
      package {
        name
        ecosystem
      }
      severity
      updatedAt
      vulnerableVersionRange
    }
  }
}"""
