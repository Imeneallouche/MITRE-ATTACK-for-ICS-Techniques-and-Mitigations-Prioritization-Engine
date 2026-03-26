"""
MITRE ATT&CK ICS Technique Statistics Generator
Extracts comprehensive statistics for each technique from Neo4j Knowledge Graph
and exports to Excel
"""

import pandas as pd
from neo4j import GraphDatabase
import logging
from typing import Dict, List, Any
from datetime import datetime

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class TechniqueStatisticsGenerator:
    """Generates comprehensive statistics for MITRE ATT&CK ICS Techniques"""
    
    def __init__(self, uri: str, username: str, password: str):
        """
        Initialize Neo4j connection
        
        Args:
            uri: Neo4j database URI
            username: Neo4j username
            password: Neo4j password
        """
        self.driver = GraphDatabase.driver(uri, auth=(username, password))
        logger.info(f"Connected to Neo4j at {uri}")
    
    def close(self):
        """Close Neo4j connection"""
        self.driver.close()
        logger.info("Neo4j connection closed")
    
    def verify_database_structure(self):
        """Verify that all required nodes and relationships exist"""
        logger.info("\n=== Verifying Database Structure ===")
        
        with self.driver.session() as session:
            # Check node counts
            node_types = ['Technique', 'Asset', 'Software', 'Campaign', 'Group', 
                         'Mitigation', 'DetectionStrategy', 'Analytic', 'DataComponent']
            
            for node_type in node_types:
                result = session.run(f"MATCH (n:{node_type}) RETURN count(n) as count")
                count = result.single()['count']
                status = "✓" if count > 0 else "✗"
                logger.info(f"{status} {node_type}: {count} nodes")
            
            # Check relationship counts
            logger.info("\n=== Verifying Relationships ===")
            relationships = [
                ("Technique", "TARGETS", "Asset"),
                ("Software", "USES", "Technique"),
                ("Campaign", "USES", "Technique"),
                ("Group", "USES", "Technique"),
                ("Mitigation", "MITIGATES", "Technique"),
                ("DetectionStrategy", "DETECTS", "Technique"),
                ("DetectionStrategy", "CONTAINS", "Analytic"),
                ("Analytic", "USES", "DataComponent")
            ]
            
            for source, rel, target in relationships:
                result = session.run(f"""
                    MATCH (s:{source})-[r:{rel}]->(t:{target})
                    RETURN count(r) as count
                """)
                count = result.single()['count']
                status = "✓" if count > 0 else "✗"
                logger.info(f"{status} {source} -[{rel}]-> {target}: {count}")
    
    def get_all_techniques(self) -> List[Dict[str, Any]]:
        """
        Get all techniques with their basic information
        
        Returns:
            List of dictionaries containing technique ID and name
        """
        logger.info("\n=== Fetching All Techniques ===")
        
        with self.driver.session() as session:
            result = session.run("""
                MATCH (t:Technique)
                RETURN t.id as id, t.name as name
                ORDER BY t.id
            """)
            
            techniques = [dict(record) for record in result]
            logger.info(f"Found {len(techniques)} techniques")
            
            return techniques
    
    def get_technique_statistics(self, technique_id: str) -> Dict[str, Any]:
        """
        Get comprehensive statistics for a specific technique
        
        Args:
            technique_id: The technique ID (e.g., 'T0800')
            
        Returns:
            Dictionary with all statistics for the technique
        """
        with self.driver.session() as session:
            # Single comprehensive query to get all statistics
            result = session.run("""
                MATCH (t:Technique {id: $tech_id})
                
                // Count targeted assets
                OPTIONAL MATCH (t)-[:TARGETS]->(asset:Asset)
                WITH t, count(DISTINCT asset) as num_assets
                
                // Count software using this technique
                OPTIONAL MATCH (software:Software)-[:USES]->(t)
                WITH t, num_assets, count(DISTINCT software) as num_software
                
                // Count campaigns using this technique
                OPTIONAL MATCH (campaign:Campaign)-[:USES]->(t)
                WITH t, num_assets, num_software, count(DISTINCT campaign) as num_campaigns
                
                // Count groups using this technique
                OPTIONAL MATCH (group:Group)-[:USES]->(t)
                WITH t, num_assets, num_software, num_campaigns, count(DISTINCT group) as num_groups
                
                // Count mitigations for this technique
                OPTIONAL MATCH (mitigation:Mitigation)-[:MITIGATES]->(t)
                WITH t, num_assets, num_software, num_campaigns, num_groups, 
                     count(DISTINCT mitigation) as num_mitigations
                
                // Count data components that detect this technique
                // Path: DetectionStrategy -[DETECTS]-> Technique
                //       DetectionStrategy -[CONTAINS]-> Analytic -[USES]-> DataComponent
                OPTIONAL MATCH (ds:DetectionStrategy)-[:DETECTS]->(t)
                OPTIONAL MATCH (ds)-[:CONTAINS]->(analytic:Analytic)-[:USES]->(dc:DataComponent)
                WITH t, num_assets, num_software, num_campaigns, num_groups, num_mitigations,
                     count(DISTINCT dc) as num_datacomponents
                
                RETURN 
                    t.id as technique_id,
                    t.name as technique_name,
                    num_assets,
                    num_software,
                    num_campaigns,
                    num_groups,
                    num_mitigations,
                    num_datacomponents
            """, tech_id=technique_id)
            
            record = result.single()
            
            if record:
                return {
                    'technique_id': record['technique_id'],
                    'technique_name': record['technique_name'],
                    'num_targeted_assets': record['num_assets'],
                    'num_software': record['num_software'],
                    'num_campaigns': record['num_campaigns'],
                    'num_groups': record['num_groups'],
                    'num_mitigations': record['num_mitigations'],
                    'num_datacomponents': record['num_datacomponents']
                }
            else:
                return None
    
    def generate_statistics_dataframe(self) -> pd.DataFrame:
        """
        Generate complete statistics for all techniques
        
        Returns:
            DataFrame with statistics for all techniques
        """
        logger.info("\n=== Generating Technique Statistics ===")
        
        # Get all techniques
        techniques = self.get_all_techniques()
        
        # Collect statistics for each technique
        all_stats = []
        
        for idx, technique in enumerate(techniques, 1):
            technique_id = technique['id']
            
            logger.info(f"Processing [{idx}/{len(techniques)}]: {technique_id} - {technique['name']}")
            
            stats = self.get_technique_statistics(technique_id)
            
            if stats:
                all_stats.append(stats)
            else:
                logger.warning(f"  ⚠ Could not get statistics for {technique_id}")
        
        # Create DataFrame
        df = pd.DataFrame(all_stats)
        
        # Reorder and rename columns for better presentation
        df = df[[
            'technique_name',
            'technique_id',
            'num_targeted_assets',
            'num_software',
            'num_campaigns',
            'num_groups',
            'num_mitigations',
            'num_datacomponents'
        ]]
        
        # Rename columns to more readable names
        df.columns = [
            'Technique Name',
            'Technique ID',
            'Number of Targeted Assets',
            'Number of Software Using Technique',
            'Number of Campaigns Using Technique',
            'Number of Groups Using Technique',
            'Number of Mitigations',
            'Number of Data Components (Detection)'
        ]
        
        return df
    
    def display_summary_statistics(self, df: pd.DataFrame):
        """Display summary statistics about the data"""
        logger.info("\n" + "="*70)
        logger.info("=== Summary Statistics ===")
        logger.info("="*70)
        
        logger.info(f"\nTotal Techniques: {len(df)}")
        
        # Statistics for each metric
        metrics = [
            ('Number of Targeted Assets', 'Assets'),
            ('Number of Software Using Technique', 'Software'),
            ('Number of Campaigns Using Technique', 'Campaigns'),
            ('Number of Groups Using Technique', 'Groups'),
            ('Number of Mitigations', 'Mitigations'),
            ('Number of Data Components (Detection)', 'Data Components')
        ]
        
        logger.info("\nDistribution of Relationships:")
        logger.info("-" * 70)
        
        for col, label in metrics:
            total = df[col].sum()
            avg = df[col].mean()
            max_val = df[col].max()
            min_val = df[col].min()
            techniques_with = (df[col] > 0).sum()
            techniques_without = (df[col] == 0).sum()
            
            logger.info(f"\n{label}:")
            logger.info(f"  Total: {total}")
            logger.info(f"  Average per technique: {avg:.2f}")
            logger.info(f"  Range: {min_val} - {max_val}")
            logger.info(f"  Techniques with {label.lower()}: {techniques_with}")
            logger.info(f"  Techniques without {label.lower()}: {techniques_without}")
        
        # Top techniques by different metrics
        logger.info("\n" + "="*70)
        logger.info("=== Top 5 Techniques by Category ===")
        logger.info("="*70)
        
        for col, label in metrics:
            logger.info(f"\nTop 5 by {label}:")
            top_5 = df.nlargest(5, col)[['Technique ID', 'Technique Name', col]]
            for idx, row in top_5.iterrows():
                logger.info(f"  {row['Technique ID']}: {row['Technique Name']} ({row[col]})")
        
        # Techniques with no relationships
        logger.info("\n" + "="*70)
        logger.info("=== Techniques with Limited Coverage ===")
        logger.info("="*70)
        
        # Techniques with no mitigations
        no_mitigations = df[df['Number of Mitigations'] == 0]
        logger.info(f"\nTechniques without mitigations: {len(no_mitigations)}")
        if len(no_mitigations) > 0 and len(no_mitigations) <= 10:
            for idx, row in no_mitigations.iterrows():
                logger.info(f"  - {row['Technique ID']}: {row['Technique Name']}")
        
        # Techniques with no detection
        no_detection = df[df['Number of Data Components (Detection)'] == 0]
        logger.info(f"\nTechniques without data component detection: {len(no_detection)}")
        if len(no_detection) > 0 and len(no_detection) <= 10:
            for idx, row in no_detection.iterrows():
                logger.info(f"  - {row['Technique ID']}: {row['Technique Name']}")
        
        # Techniques not used by any threat actor
        no_usage = df[(df['Number of Software Using Technique'] == 0) & 
                      (df['Number of Campaigns Using Technique'] == 0) & 
                      (df['Number of Groups Using Technique'] == 0)]
        logger.info(f"\nTechniques not observed in the wild: {len(no_usage)}")
        if len(no_usage) > 0 and len(no_usage) <= 10:
            for idx, row in no_usage.iterrows():
                logger.info(f"  - {row['Technique ID']}: {row['Technique Name']}")
    
    def export_to_excel(self, df: pd.DataFrame, output_file: str):
        """
        Export statistics to Excel with formatting
        
        Args:
            df: DataFrame with technique statistics
            output_file: Path to output Excel file
        """
        logger.info(f"\n=== Exporting to Excel ===")
        logger.info(f"Output file: {output_file}")
        
        try:
            # Create Excel writer with openpyxl engine for better formatting
            with pd.ExcelWriter(output_file, engine='openpyxl') as writer:
                # Write main statistics sheet
                df.to_excel(writer, sheet_name='Technique Statistics', index=False)
                
                # Get workbook and worksheet for formatting
                workbook = writer.book
                worksheet = writer.sheets['Technique Statistics']
                
                # Auto-adjust column widths
                for idx, col in enumerate(df.columns, 1):
                    max_length = max(
                        df[col].astype(str).apply(len).max(),
                        len(col)
                    )
                    # Add some padding
                    adjusted_width = min(max_length + 2, 50)
                    worksheet.column_dimensions[chr(64 + idx)].width = adjusted_width
                
                # Format header row
                for cell in worksheet[1]:
                    cell.font = cell.font.copy(bold=True)
                
                # Add summary sheet
                summary_data = {
                    'Metric': ['Total Techniques', 'Total Assets Targeted', 'Total Software', 
                              'Total Campaigns', 'Total Groups', 'Total Mitigations', 
                              'Total Data Components'],
                    'Count': [
                        len(df),
                        df['Number of Targeted Assets'].sum(),
                        df['Number of Software Using Technique'].sum(),
                        df['Number of Campaigns Using Technique'].sum(),
                        df['Number of Groups Using Technique'].sum(),
                        df['Number of Mitigations'].sum(),
                        df['Number of Data Components (Detection)'].sum()
                    ]
                }
                summary_df = pd.DataFrame(summary_data)
                summary_df.to_excel(writer, sheet_name='Summary', index=False)
                
                # Format summary sheet
                summary_ws = writer.sheets['Summary']
                summary_ws.column_dimensions['A'].width = 40
                summary_ws.column_dimensions['B'].width = 15
                for cell in summary_ws[1]:
                    cell.font = cell.font.copy(bold=True)
            
            logger.info(f"✓ Successfully exported to {output_file}")
            
        except Exception as e:
            logger.error(f"✗ Error exporting to Excel: {e}")
            raise
    
    def generate_report(self, output_file: str = "technique_statistics.xlsx"):
        """
        Main method to generate complete technique statistics report
        
        Args:
            output_file: Path to output Excel file
        """
        logger.info("="*70)
        logger.info("MITRE ATT&CK ICS - Technique Statistics Generator")
        logger.info("="*70)
        
        try:
            # Verify database structure
            self.verify_database_structure()
            
            # Generate statistics
            df = self.generate_statistics_dataframe()
            
            if df.empty:
                logger.error("✗ No data retrieved from database")
                return
            
            logger.info(f"\n✓ Generated statistics for {len(df)} techniques")
            
            # Display summary
            self.display_summary_statistics(df)
            
            # Export to Excel
            self.export_to_excel(df, output_file)
            
            logger.info("\n" + "="*70)
            logger.info("✓ Report generation completed successfully!")
            logger.info("="*70)
            
            # Display sample of data
            logger.info("\n=== Sample Data (First 5 Techniques) ===")
            print("\n" + df.head().to_string(index=False))
            
        except Exception as e:
            logger.error(f"✗ Error generating report: {e}")
            raise


def main():
    """Main execution function"""
    
    # Configuration - UPDATE THESE VALUES
    NEO4J_URI = "neo4j+s://77d567c6.databases.neo4j.io"
    NEO4J_USERNAME = "neo4j"
    NEO4J_PASSWORD = "2R3cG5YrBs79WDKkGGXUdRrcFB9h65WQoxN6_3QrtBo"
    OUTPUT_FILE = "technique_statistics.xlsx"
    
    print("""
    ╔══════════════════════════════════════════════════════════════╗
    ║   MITRE ATT&CK ICS - Technique Statistics Generator          ║
    ║                                                              ║
    ║   Generates comprehensive statistics for each technique:     ║
    ║   - Targeted Assets                                          ║
    ║   - Software, Campaigns, Groups using technique              ║
    ║   - Mitigations                                              ║
    ║   - Data Components (Detection)                              ║
    ╚══════════════════════════════════════════════════════════════╝
    """)
    
    # Create generator instance
    generator = TechniqueStatisticsGenerator(
        uri=NEO4J_URI,
        username=NEO4J_USERNAME,
        password=NEO4J_PASSWORD
    )
    
    try:
        # Generate the report
        generator.generate_report(OUTPUT_FILE)
        
        # Show example queries for manual exploration
        logger.info("\n=== Example Queries for Manual Exploration ===")
        logger.info("""
1. Find techniques with the most mitigations:
   MATCH (m:Mitigation)-[:MITIGATES]->(t:Technique)
   RETURN t.id, t.name, count(m) as num_mitigations
   ORDER BY num_mitigations DESC
   LIMIT 10

2. Find techniques targeting critical assets:
   MATCH (t:Technique)-[:TARGETS]->(a:Asset)
   RETURN t.id, t.name, collect(a.name) as targeted_assets
   ORDER BY size(targeted_assets) DESC

3. Find techniques used by multiple threat actors:
   MATCH (g:Group)-[:USES]->(t:Technique)
   RETURN t.id, t.name, count(g) as num_groups
   ORDER BY num_groups DESC
   LIMIT 10

4. Find techniques with comprehensive detection:
   MATCH (ds:DetectionStrategy)-[:DETECTS]->(t:Technique)
   MATCH (ds)-[:CONTAINS]->(a:Analytic)-[:USES]->(dc:DataComponent)
   RETURN t.id, t.name, count(DISTINCT dc) as num_datacomponents
   ORDER BY num_datacomponents DESC
   LIMIT 10

5. Find techniques without mitigations:
   MATCH (t:Technique)
   WHERE NOT EXISTS((m:Mitigation)-[:MITIGATES]->(t))
   RETURN t.id, t.name

6. Find attack paths with full context:
   MATCH (g:Group)-[:USES]->(t:Technique)-[:TARGETS]->(a:Asset)
   MATCH (m:Mitigation)-[:MITIGATES]->(t)
   RETURN g.name, t.name, a.name, collect(m.name) as mitigations
   LIMIT 10
        """)
        
    finally:
        # Close connection
        generator.close()


if __name__ == "__main__":
    """
    Usage:
    1. Install required packages:
       pip install pandas openpyxl neo4j
    
    2. Ensure Neo4j database is running with the complete knowledge graph
    
    3. Update configuration in main() function:
       - NEO4J_URI: Your Neo4j connection URI
       - NEO4J_USERNAME: Your Neo4j username
       - NEO4J_PASSWORD: Your Neo4j password
       - OUTPUT_FILE: Desired output file name
    
    4. Run the script:
       python technique_statistics.py
    
    Output:
    - Excel file with two sheets:
      1. "Technique Statistics": Complete statistics for all techniques
      2. "Summary": Overall summary statistics
    
    The script generates statistics for each technique including:
    - Technique Name and ID
    - Number of Targeted Assets
    - Number of Software using the technique
    - Number of Campaigns using the technique
    - Number of Groups using the technique
    - Number of Mitigations
    - Number of Data Components for detection
    """
    main()