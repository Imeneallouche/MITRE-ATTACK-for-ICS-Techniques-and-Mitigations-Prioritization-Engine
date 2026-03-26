"""
MITRE ATT&CK ICS Technique Priority Scoring using MCDM
Implements the Multi-Criteria Decision-Making approach from the research paper
with an additional criterion for asset impact (C4)
"""

import pandas as pd
import numpy as np
import logging
from typing import Dict, Tuple
import warnings

warnings.filterwarnings('ignore')

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class TechniquePriorityScorer:
    """
    Implements MCDM-based technique prioritization using:
    - C1: Impact (based on mitigation difficulty)
    - C2: Threat Score (based on threat intelligence)
    - C3: Security Control Gap (based on detection difficulty)
    - C4: Asset Impact (based on number of targeted assets)
    """
    
    def __init__(self, statistics_file: str):
        """
        Initialize the scorer with technique statistics
        
        Args:
            statistics_file: Path to Excel file with technique statistics
        """
        self.statistics_file = statistics_file
        self.df = None
        self.decision_matrix = None
        self.normalized_matrix = None
        self.weights = None
        self.priority_scores = None
        
    def load_data(self):
        """Load technique statistics from Excel file"""
        logger.info(f"Loading data from {self.statistics_file}")
        
        try:
            self.df = pd.read_excel(self.statistics_file, sheet_name='Technique Statistics')
            logger.info(f"✓ Loaded {len(self.df)} techniques")
            
            # Verify required columns exist
            required_columns = [
                'Technique Name',
                'Technique ID',
                'Number of Targeted Assets',
                'Number of Software Using Technique',
                'Number of Campaigns Using Technique',
                'Number of Groups Using Technique',
                'Number of Mitigations',
                'Number of Data Components (Detection)'
            ]
            
            missing_columns = [col for col in required_columns if col not in self.df.columns]
            if missing_columns:
                logger.error(f"✗ Missing required columns: {missing_columns}")
                return False
            
            logger.info("✓ All required columns present")
            return True
            
        except FileNotFoundError:
            logger.error(f"✗ File not found: {self.statistics_file}")
            return False
        except Exception as e:
            logger.error(f"✗ Error loading data: {e}")
            return False
    
    def compute_criteria(self):
        """
        Compute the four prioritization criteria for each technique
        
        C1: Impact = 1 / (Mitigation Count + 1)
        C2: Threat Score = ln(Groups + 1) + ln(Campaigns + 1) + ln(Software + 1)
        C3: Security Control Gap = 1 / (Detection Count + 1)
        C4: Asset Impact = ln(Assets + 1)
        """
        logger.info("\n=== Computing Prioritization Criteria ===")
        
        # C1: Impact (inverse of mitigations)
        self.df['C1_Impact'] = 1 / (self.df['Number of Mitigations'] + 1)
        logger.info("✓ Computed C1: Impact")
        
        # C2: Threat Score (log-transformed sum of threat intelligence)
        self.df['C2_Threat_Score'] = (
            np.log(self.df['Number of Groups Using Technique'] + 1) +
            np.log(self.df['Number of Campaigns Using Technique'] + 1) +
            np.log(self.df['Number of Software Using Technique'] + 1)
        )
        logger.info("✓ Computed C2: Threat Score")
        
        # C3: Security Control Gap (inverse of detections)
        self.df['C3_Control_Gap'] = 1 / (self.df['Number of Data Components (Detection)'] + 1)
        logger.info("✓ Computed C3: Security Control Gap")
        
        # C4: Asset Impact (log-transformed number of assets)
        self.df['C4_Asset_Impact'] = np.log(self.df['Number of Targeted Assets'] + 1)
        logger.info("✓ Computed C4: Asset Impact")
        
        # Create decision matrix
        self.decision_matrix = self.df[['C1_Impact', 'C2_Threat_Score', 
                                        'C3_Control_Gap', 'C4_Asset_Impact']].values
        
        logger.info(f"\nDecision matrix shape: {self.decision_matrix.shape}")
        
        # Display statistics for each criterion
        logger.info("\n=== Criterion Statistics ===")
        for col in ['C1_Impact', 'C2_Threat_Score', 'C3_Control_Gap', 'C4_Asset_Impact']:
            logger.info(f"\n{col}:")
            logger.info(f"  Min: {self.df[col].min():.4f}")
            logger.info(f"  Max: {self.df[col].max():.4f}")
            logger.info(f"  Mean: {self.df[col].mean():.4f}")
            logger.info(f"  Std: {self.df[col].std():.4f}")
    
    def normalize_matrix(self):
        """
        Normalize the decision matrix using proportional normalization
        p_ij = x_ij / sum(x_ij) for each column j
        """
        logger.info("\n=== Normalizing Decision Matrix ===")
        
        # Column-wise normalization
        column_sums = self.decision_matrix.sum(axis=0)
        self.normalized_matrix = self.decision_matrix / column_sums
        
        logger.info("✓ Matrix normalized using proportional normalization")
        
        # Verify normalization (each column should sum to 1)
        col_sums = self.normalized_matrix.sum(axis=0)
        logger.info(f"Column sums after normalization: {col_sums}")
    
    def compute_entropy_weights(self):
        """
        Compute objective weights using Entropy Weight Method (EWM)
        
        Steps:
        1. Calculate entropy: E_j = -k * sum(p_ij * ln(p_ij))
        2. Calculate divergence: d_j = 1 - E_j
        3. Calculate weights: w_j = d_j / sum(d_j)
        """
        logger.info("\n=== Computing Entropy Weights ===")
        
        m, n = self.normalized_matrix.shape  # m = techniques, n = criteria
        k = 1 / np.log(m)  # Constant for entropy calculation
        
        # Calculate entropy for each criterion
        entropies = []
        
        for j in range(n):
            # Handle zero values to avoid log(0)
            p_col = self.normalized_matrix[:, j].copy()
            p_col[p_col == 0] = 1e-10  # Replace zeros with small value
            
            # Calculate entropy: E_j = -k * sum(p_ij * ln(p_ij))
            entropy_j = -k * np.sum(p_col * np.log(p_col))
            entropies.append(entropy_j)
        
        entropies = np.array(entropies)
        
        # Calculate divergence (degree of differentiation)
        divergences = 1 - entropies
        
        # Calculate weights
        self.weights = divergences / divergences.sum()
        
        # Display results
        criteria_names = ['C1 (Impact)', 'C2 (Threat Score)', 
                         'C3 (Control Gap)', 'C4 (Asset Impact)']
        
        logger.info("\nEntropy Analysis Results:")
        logger.info("-" * 70)
        for i, name in enumerate(criteria_names):
            logger.info(f"{name}:")
            logger.info(f"  Entropy (E_j):     {entropies[i]:.4f}")
            logger.info(f"  Divergence (d_j):  {divergences[i]:.4f}")
            logger.info(f"  Weight (w_j):      {self.weights[i]:.4f}")
        
        # Verify weights sum to 1
        logger.info(f"\nSum of weights: {self.weights.sum():.4f}")
        logger.info("✓ Entropy weights computed successfully")
    
    def compute_priority_scores(self):
        """
        Compute final priority scores using Weighted Sum Method (WSM)
        PS_i = sum(w_j * p_ij) for each technique i
        """
        logger.info("\n=== Computing Priority Scores ===")
        
        # Calculate weighted sum for each technique
        self.priority_scores = np.dot(self.normalized_matrix, self.weights)
        
        # Add to dataframe
        self.df['Priority_Score_Raw'] = self.priority_scores
        
        # Normalize scores to [0, 1] range for better interpretation
        ps_min = self.priority_scores.min()
        ps_max = self.priority_scores.max()
        self.df['Priority_Score_Normalized'] = (
            (self.priority_scores - ps_min) / (ps_max - ps_min)
        )
        
        # Rank techniques
        self.df['Priority_Rank'] = self.df['Priority_Score_Normalized'].rank(
            ascending=False, method='min'
        ).astype(int)
        
        logger.info(f"✓ Priority scores computed for {len(self.df)} techniques")
        logger.info(f"  Raw score range: [{ps_min:.6f}, {ps_max:.6f}]")
        logger.info(f"  Normalized range: [0.0, 1.0]")
    
    def display_results_summary(self):
        """Display summary of prioritization results"""
        logger.info("\n" + "=" * 70)
        logger.info("=== PRIORITIZATION RESULTS SUMMARY ===")
        logger.info("=" * 70)
        
        # Top 10 techniques
        logger.info("\nTop 10 Highest Priority Techniques:")
        logger.info("-" * 70)
        
        top_10 = self.df.nsmallest(10, 'Priority_Rank')[[
            'Priority_Rank', 'Technique ID', 'Technique Name', 
            'Priority_Score_Normalized', 'C1_Impact', 'C2_Threat_Score',
            'C3_Control_Gap', 'C4_Asset_Impact'
        ]]
        
        for idx, row in top_10.iterrows():
            logger.info(f"\n[{row['Priority_Rank']}] {row['Technique ID']}: {row['Technique Name']}")
            logger.info(f"    Priority Score: {row['Priority_Score_Normalized']:.4f}")
            logger.info(f"    C1 (Impact):    {row['C1_Impact']:.4f}")
            logger.info(f"    C2 (Threat Score): {row['C2_Threat_Score']:.4f}")
            logger.info(f"    C3 (Control Gap):  {row['C3_Control_Gap']:.4f}")
            logger.info(f"    C4 (Asset Impact): {row['C4_Asset_Impact']:.4f}")
        
        # Bottom 5 techniques
        logger.info("\n" + "-" * 70)
        logger.info("Bottom 5 Lowest Priority Techniques:")
        logger.info("-" * 70)
        
        bottom_5 = self.df.nlargest(5, 'Priority_Rank')[[
            'Priority_Rank', 'Technique ID', 'Technique Name', 
            'Priority_Score_Normalized'
        ]]
        
        for idx, row in bottom_5.iterrows():
            logger.info(f"[{row['Priority_Rank']}] {row['Technique ID']}: {row['Technique Name']} "
                       f"(Score: {row['Priority_Score_Normalized']:.4f})")
        
        # Score distribution
        logger.info("\n" + "=" * 70)
        logger.info("Priority Score Distribution:")
        logger.info("=" * 70)
        
        score_bins = [0, 0.2, 0.4, 0.6, 0.8, 1.0]
        score_labels = ['Very Low (0.0-0.2)', 'Low (0.2-0.4)', 
                       'Medium (0.4-0.6)', 'High (0.6-0.8)', 
                       'Very High (0.8-1.0)']
        
        self.df['Priority_Category'] = pd.cut(
            self.df['Priority_Score_Normalized'],
            bins=score_bins,
            labels=score_labels,
            include_lowest=True
        )
        
        distribution = self.df['Priority_Category'].value_counts().sort_index()
        for category, count in distribution.items():
            percentage = (count / len(self.df)) * 100
            logger.info(f"  {category}: {count} techniques ({percentage:.1f}%)")
    
    def export_results(self, output_file: str = "technique_priority_scores.xlsx"):
        """
        Export results to Excel with multiple sheets
        
        Args:
            output_file: Path to output Excel file
        """
        logger.info(f"\n=== Exporting Results to {output_file} ===")
        
        try:
            with pd.ExcelWriter(output_file, engine='openpyxl') as writer:
                # Sheet 1: Complete results with all columns
                output_df = self.df[[
                    'Priority_Rank',
                    'Technique ID',
                    'Technique Name',
                    'Priority_Score_Normalized',
                    'Priority_Score_Raw',
                    'C1_Impact',
                    'C2_Threat_Score',
                    'C3_Control_Gap',
                    'C4_Asset_Impact',
                    'Number of Targeted Assets',
                    'Number of Software Using Technique',
                    'Number of Campaigns Using Technique',
                    'Number of Groups Using Technique',
                    'Number of Mitigations',
                    'Number of Data Components (Detection)'
                ]].sort_values('Priority_Rank')
                
                output_df.to_excel(writer, sheet_name='Priority Scores', index=False)
                
                # Sheet 2: Top 20 techniques
                top_20 = output_df.head(20)
                top_20.to_excel(writer, sheet_name='Top 20 Techniques', index=False)
                
                # Sheet 3: Methodology and weights
                methodology_data = {
                    'Criterion': [
                        'C1: Impact',
                        'C2: Threat Score',
                        'C3: Security Control Gap',
                        'C4: Asset Impact'
                    ],
                    'Formula': [
                        '1 / (Mitigation Count + 1)',
                        'ln(Groups + 1) + ln(Campaigns + 1) + ln(Software + 1)',
                        '1 / (Detection Count + 1)',
                        'ln(Assets + 1)'
                    ],
                    'Weight (EWM)': self.weights,
                    'Interpretation': [
                        'Higher score = Fewer mitigations = Higher impact',
                        'Higher score = More threat actors using = Higher threat',
                        'Higher score = Fewer detections = Larger control gap',
                        'Higher score = More assets affected = Higher impact'
                    ]
                }
                
                methodology_df = pd.DataFrame(methodology_data)
                methodology_df.to_excel(writer, sheet_name='Methodology', index=False)
                
                # Sheet 4: Summary statistics
                summary_data = {
                    'Metric': [
                        'Total Techniques Analyzed',
                        'Average Priority Score',
                        'Highest Priority Score',
                        'Lowest Priority Score',
                        'Techniques with Score > 0.8',
                        'Techniques with Score > 0.6',
                        'Techniques with Score < 0.2'
                    ],
                    'Value': [
                        len(self.df),
                        f"{self.df['Priority_Score_Normalized'].mean():.4f}",
                        f"{self.df['Priority_Score_Normalized'].max():.4f}",
                        f"{self.df['Priority_Score_Normalized'].min():.4f}",
                        len(self.df[self.df['Priority_Score_Normalized'] > 0.8]),
                        len(self.df[self.df['Priority_Score_Normalized'] > 0.6]),
                        len(self.df[self.df['Priority_Score_Normalized'] < 0.2])
                    ]
                }
                
                summary_df = pd.DataFrame(summary_data)
                summary_df.to_excel(writer, sheet_name='Summary', index=False)
                
                # Format worksheets
                for sheet_name in writer.sheets:
                    worksheet = writer.sheets[sheet_name]
                    
                    # Auto-adjust column widths
                    for column in worksheet.columns:
                        max_length = 0
                        column_letter = column[0].column_letter
                        
                        for cell in column:
                            try:
                                if len(str(cell.value)) > max_length:
                                    max_length = len(str(cell.value))
                            except:
                                pass
                        
                        adjusted_width = min(max_length + 2, 50)
                        worksheet.column_dimensions[column_letter].width = adjusted_width
                    
                    # Bold header row
                    for cell in worksheet[1]:
                        cell.font = cell.font.copy(bold=True)
            
            logger.info(f"✓ Results exported successfully to {output_file}")
            logger.info("  Sheets created:")
            logger.info("    1. Priority Scores - Complete results")
            logger.info("    2. Top 20 Techniques - Highest priority techniques")
            logger.info("    3. Methodology - Criteria formulas and weights")
            logger.info("    4. Summary - Statistical overview")
            
        except Exception as e:
            logger.error(f"✗ Error exporting results: {e}")
            raise
    
    def run_complete_analysis(self, output_file: str = "technique_priority_scores.xlsx"):
        """
        Run the complete prioritization analysis
        
        Args:
            output_file: Path to output Excel file
        """
        logger.info("=" * 70)
        logger.info("MITRE ATT&CK ICS Technique Priority Scoring")
        logger.info("Using Multi-Criteria Decision-Making (MCDM) Approach")
        logger.info("=" * 70)
        
        # Step 1: Load data
        if not self.load_data():
            return False
        
        # Step 2: Compute criteria
        self.compute_criteria()
        
        # Step 3: Normalize decision matrix
        self.normalize_matrix()
        
        # Step 4: Compute entropy weights
        self.compute_entropy_weights()
        
        # Step 5: Compute priority scores
        self.compute_priority_scores()
        
        # Step 6: Display results
        self.display_results_summary()
        
        # Step 7: Export results
        self.export_results(output_file)
        
        logger.info("\n" + "=" * 70)
        logger.info("✓ Complete analysis finished successfully!")
        logger.info("=" * 70)
        
        return True


def main():
    """Main execution function"""
    
    # Configuration
    INPUT_FILE = "input/technique_statistics.xlsx"  # Output from previous script
    OUTPUT_FILE = "output/technique_priority_scores.xlsx"
    
    print("""
    ╔══════════════════════════════════════════════════════════════╗
    ║  MITRE ATT&CK ICS - Technique Priority Scoring (MCDM)        ║
    ║                                                              ║
    ║  Implementation of research paper methodology with:          ║
    ║  - C1: Impact (mitigation difficulty)                        ║
    ║  - C2: Threat Score (threat intelligence)                    ║
    ║  - C3: Security Control Gap (detection difficulty)           ║
    ║  - C4: Asset Impact (number of affected assets) [NEW]        ║
    ║                                                              ║
    ║  Using Entropy Weight Method (EWM) + Weighted Sum Method     ║
    ╚══════════════════════════════════════════════════════════════╝
    """)
    
    # Create scorer instance
    scorer = TechniquePriorityScorer(INPUT_FILE)
    
    # Run analysis
    success = scorer.run_complete_analysis(OUTPUT_FILE)
    
    if success:
        logger.info("\n📊 Analysis Results:")
        logger.info(f"   Input file:  {INPUT_FILE}")
        logger.info(f"   Output file: {OUTPUT_FILE}")
        logger.info("\n✓ You can now use these priority scores for adversary emulation planning!")


if __name__ == "__main__":
    """
    Usage:
    1. Install required packages:
       pip install pandas openpyxl numpy
    
    2. Ensure you have the technique statistics file from the previous script
    
    3. Run the script:
       python technique_priority_scorer.py
    
    Input File Requirements:
    - Excel file with sheet "Technique Statistics"
    - Must contain columns:
      * Technique Name
      * Technique ID
      * Number of Targeted Assets
      * Number of Software Using Technique
      * Number of Campaigns Using Technique
      * Number of Groups Using Technique
      * Number of Mitigations
      * Number of Data Components (Detection)
    
    Output File Structure:
    - Sheet 1: Complete priority scores for all techniques
    - Sheet 2: Top 20 highest priority techniques
    - Sheet 3: Methodology and criterion weights
    - Sheet 4: Summary statistics
    
    Methodology:
    Based on the research paper's MCDM approach:
    1. Compute four criteria (C1-C4) for each technique
    2. Normalize using proportional normalization
    3. Calculate objective weights using Entropy Weight Method
    4. Compute priority scores using Weighted Sum Method
    5. Rank techniques by normalized priority score
    """
    main()