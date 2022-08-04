# Rapid7_InsightVM

This script helps in finding a specific vulnerability across all the sites

    QUERIES = {
        "vulnerabilities": """
            SELECT dvr.reference, asset_id, da.ip_address, da.host_name, da.mac_address, round(dv.riskscore::numeric, 0) AS risk
            FROM fact_asset_vulnerability_finding favf 
               JOIN dim_asset da USING (asset_id) 
               JOIN dim_vulnerability dv USING (vulnerability_id) 
               JOIN dim_vulnerability_reference dvr using (vulnerability_id) 
            WHERE dvr.reference in ('CVE-2022-30190')
            ORDER BY da.ip_address ASC, dv.title ASC
        """
    }

Please pass insightVM creds 
