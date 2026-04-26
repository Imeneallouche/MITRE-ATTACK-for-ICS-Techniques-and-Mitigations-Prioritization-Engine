"""
MITRE ATT&CK ICS Technique Priority Scoring (Threat-Only)
Now uses a single criterion:
- C2: Threat Score = ln(Groups + 1) + ln(Campaigns + 1) + ln(Software + 1)
Weights are still computed with EWM (single criterion => weight = 1).
"""

import pandas as pd
import numpy as np
import logging
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
    Technique prioritization using only:
    - C2: Threat Score (based on threat intelligence)
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

            # Required columns for threat-only scoring
            required_columns = [
                'Technique Name',
                'Technique ID',
                'Number of Software Using Technique',
                'Number of Campaigns Using Technique',
                'Number of Groups Using Technique'
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
        Compute the threat-only criterion for each technique

        C2: Threat Score = ln(Groups + 1) + ln(Campaigns + 1) + ln(Software + 1)
        """
        logger.info("\n=== Computing Threat Score (C2) ===")

        # C2: Threat Score (log-transformed sum of threat intelligence)
        self.df['C2_Threat_Score'] = (
            np.log(self.df['Number of Groups Using Technique'] + 1) +
            np.log(self.df['Number of Campaigns Using Technique'] + 1) +
            np.log(self.df['Number of Software Using Technique'] + 1)
        )
        logger.info("✓ Computed C2: Threat Score")

        # Decision matrix with a single column (C2)
        self.decision_matrix = self.df[['C2_Threat_Score']].values
        logger.info(f"\nDecision matrix shape: {self.decision_matrix.shape}")

        # Display statistics for the criterion
        logger.info("\n=== Criterion Statistics ===")
        col = 'C2_Threat_Score'
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
        column_sums[column_sums == 0] = 1e-12  # avoid divide-by-zero
        self.normalized_matrix = self.decision_matrix / column_sums

        logger.info("✓ Matrix normalized using proportional normalization")

        # Verify normalization (each column should sum to 1)
        col_sums = self.normalized_matrix.sum(axis=0)
        logger.info(f"Column sums after normalization: {col_sums}")

    def compute_entropy_weights(self):
        """
        Compute objective weights using Entropy Weight Method (EWM).
        With one criterion this will naturally produce weight=1.
        """
        logger.info("\n=== Computing Entropy Weights ===")

        m, n = self.normalized_matrix.shape  # m = techniques, n = criteria
        if m <= 1:
            # Edge case: 0 or 1 technique -> default equal weights
            self.weights = np.ones(n) / float(n)
            logger.info("✓ Edge case: <=1 technique, using equal weights")
            return

        k = 1 / np.log(m)  # Constant for entropy calculation

        entropies = []
        for j in range(n):
            p_col = self.normalized_matrix[:, j].copy()
            p_col[p_col == 0] = 1e-10
            entropy_j = -k * np.sum(p_col * np.log(p_col))
            entropies.append(entropy_j)

        entropies = np.array(entropies)
        divergences = 1 - entropies
        if divergences.sum() == 0:
            # fallback to equal weights
            self.weights = np.ones_like(divergences) / len(divergences)
        else:
            self.weights = divergences / divergences.sum()

        # Display results
        criteria_names = ['C2 (Threat Score)']
        logger.info("\nEntropy Analysis Results:")
        logger.info("-" * 70)
        for i, name in enumerate(criteria_names):
            logger.info(f"{name}:")
            logger.info(f"  Entropy (E_j):     {entropies[i]:.4f}")
            logger.info(f"  Divergence (d_j):  {divergences[i]:.4f}")
            logger.info(f"  Weight (w_j):      {self.weights[i]:.4f}")

        logger.info(f"\nSum of weights: {self.weights.sum():.4f}")
        logger.info("✓ Entropy weights computed successfully")

    def compute_priority_scores(self):
        """
        Compute final priority scores.
        With one criterion, PS_i reduces to the normalized threat score (after weighted sum).
        """
        logger.info("\n=== Computing Priority Scores ===")

        # Weighted sum
        self.priority_scores = np.dot(self.normalized_matrix, self.weights)

        # Add to dataframe
        self.df['Priority_Score_Raw'] = self.priority_scores.flatten()

        # Normalize to [0,1]
        ps_min = self.priority_scores.min()
        ps_max = self.priority_scores.max()
        if ps_max - ps_min == 0:
            self.df['Priority_Score_Normalized'] = 0.0
        else:
            self.df['Priority_Score_Normalized'] = (
                (self.priority_scores.flatten() - ps_min) / (ps_max - ps_min)
            )

        # Rank techniques
        self.df['Priority_Rank'] = self.df['Priority_Score_Normalized'].rank(
            ascending=False, method='min'
        ).astype(int)

        logger.info(f"✓ Priority scores computed for {len(self.df)} techniques")
        logger.info(f"  Raw score range: [{ps_min:.6f}, {ps_max:.6f}]")
        logger.info("  Normalized range: [0.0, 1.0]")

    def display_results_summary(self):
        """Display summary of prioritization results (threat-only)"""
        logger.info("\n" + "=" * 70)
        logger.info("=== PRIORITIZATION RESULTS SUMMARY (THREAT ONLY) ===")
        logger.info("=" * 70)

        # Top 10 techniques
        logger.info("\nTop 10 Highest Priority Techniques:")
        logger.info("-" * 70)

        top_10 = self.df.nsmallest(10, 'Priority_Rank')[[
            'Priority_Rank', 'Technique ID', 'Technique Name',
            'Priority_Score_Normalized', 'C2_Threat_Score'
        ]]

        for idx, row in top_10.iterrows():
            logger.info(f"\n[{row['Priority_Rank']}] {row['Technique ID']}: {row['Technique Name']}")
            logger.info(f"    Priority Score: {row['Priority_Score_Normalized']:.4f}")
            logger.info(f"    C2 (Threat Score): {row['C2_Threat_Score']:.4f}")

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

    def export_results(self, output_file: str = "technique_priority_scores_threat_only.xlsx"):
        """
        Export results to Excel with multiple sheets (threat-only)
        """
        logger.info(f"\n=== Exporting Results to {output_file} ===")

        try:
            with pd.ExcelWriter(output_file, engine='openpyxl') as writer:
                # Sheet 1: Complete results with threat score
                cols_to_export = [
                    'Priority_Rank',
                    'Technique ID',
                    'Technique Name',
                    'Priority_Score_Normalized',
                    'Priority_Score_Raw',
                    'C2_Threat_Score',
                    'Number of Software Using Technique',
                    'Number of Campaigns Using Technique',
                    'Number of Groups Using Technique'
                ]
                cols_to_export = [c for c in cols_to_export if c in self.df.columns]
                output_df = self.df[cols_to_export].sort_values('Priority_Rank')
                output_df.to_excel(writer, sheet_name='Priority Scores', index=False)

                # Sheet 2: Top 20 techniques
                top_20 = output_df.head(20)
                top_20.to_excel(writer, sheet_name='Top 20 Techniques', index=False)

                # Sheet 3: Methodology and weights
                methodology_data = {
                    'Criterion': ['C2: Threat Score'],
                    'Formula': ['ln(Groups + 1) + ln(Campaigns + 1) + ln(Software + 1)'],
                    'Weight (EWM)': [float(self.weights[0])],
                    'Interpretation': ['Higher score = More threat actors/campaigns/software using the technique = Higher threat']
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
                    for cell in worksheet[1]:
                        cell.font = cell.font.copy(bold=True)

            logger.info(f"✓ Results exported successfully to {output_file}")
            logger.info("  Sheets created: Priority Scores, Top 20 Techniques, Methodology, Summary")

        except Exception as e:
            logger.error(f"✗ Error exporting results: {e}")
            raise

    def run_complete_analysis(self, output_file: str = "technique_priority_scores_threat_only.xlsx"):
        """
        Run the complete prioritization analysis (threat-only)
        """
        logger.info("=" * 70)
        logger.info("MITRE ATT&CK ICS Technique Priority Scoring (Threat-Only)")
        logger.info("=" * 70)

        if not self.load_data():
            return False

        self.compute_criteria()
        self.normalize_matrix()
        self.compute_entropy_weights()
        self.compute_priority_scores()
        self.display_results_summary()
        self.export_results(output_file)

        logger.info("\n" + "=" * 70)
        logger.info("✓ Complete analysis finished successfully!")
        logger.info("=" * 70)
        return True


def main():
    """Main execution function"""

    INPUT_FILE = "input/technique_statistics.xlsx"
    OUTPUT_FILE = "output/technique_priority_scores_v3.xlsx"

    print("""
    ╔══════════════════════════════════════════════════════════════╗
    ║  MITRE ATT&CK ICS - Technique Priority Scoring (Threat Only) ║
    ║                                                              ║
    ║  Using:                                                      ║
    ║  - C2: Threat Score (threat intelligence only)               ║
    ╚══════════════════════════════════════════════════════════════╝
    """)

    scorer = TechniquePriorityScorer(INPUT_FILE)
    success = scorer.run_complete_analysis(OUTPUT_FILE)

    if success:
        logger.info("\n📊 Analysis Results:")
        logger.info(f"   Input file:  {INPUT_FILE}")
        logger.info(f"   Output file: {OUTPUT_FILE}")
        logger.info("\n✓ Threat-only priority scores ready for use!")

if __name__ == "__main__":
    """
    Usage:
    1. Install required packages:
       pip install pandas openpyxl numpy

    2. Ensure the Excel file has sheet "Technique Statistics" with these columns:
       - Technique Name
       - Technique ID
       - Number of Software Using Technique
       - Number of Campaigns Using Technique
       - Number of Groups Using Technique

    3. Run:
       python technique_priority_scorer_threat_only.py
    """
    main()
