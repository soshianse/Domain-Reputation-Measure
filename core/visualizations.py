"""
Data Visualization Module.

Creates charts and graphs for ASN analysis using matplotlib and plotly.
"""

import logging
from typing import Dict, Any, List, Optional, Tuple
from pathlib import Path

logger = logging.getLogger(__name__)


class ASNVisualizer:
    """
    Creates visualizations for ASN analysis data.
    """

    def __init__(self, output_dir: str = 'visualizations'):
        """
        Initialize visualizer.

        Args:
            output_dir: Directory to save visualizations
        """
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(exist_ok=True)

    def plot_top_asns(
        self,
        analytics_data: Dict[str, Any],
        output_path: Optional[str] = None,
        top_n: int = 15
    ) -> str:
        """
        Create bar chart of top ASNs.

        Args:
            analytics_data: Analytics data from ASNAnalytics
            output_path: Optional custom output path
            top_n: Number of top ASNs to show

        Returns:
            Path to saved visualization
        """
        try:
            import matplotlib.pyplot as plt
            import matplotlib
            matplotlib.use('Agg')  # Non-interactive backend
        except ImportError:
            logger.error("Visualization requires matplotlib: pip install matplotlib")
            return ""

        try:
            if 'top_asns' not in analytics_data:
                logger.error("No top_asns data in analytics")
                return ""

            top_asns = analytics_data['top_asns'][:top_n]
            if not top_asns:
                logger.warning("No ASN data to visualize")
                return ""

            # Prepare data
            asn_labels = [f"AS{asn['asn']}" for asn in top_asns]
            domain_counts = [asn['domain_count'] for asn in top_asns]
            ip_counts = [asn['ip_count'] for asn in top_asns]

            # Create figure with two subplots
            fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(16, 6))

            # Plot 1: Domain count
            bars1 = ax1.barh(asn_labels, domain_counts, color='steelblue')
            ax1.set_xlabel('Number of Domains', fontsize=12)
            ax1.set_ylabel('ASN', fontsize=12)
            ax1.set_title('Top ASNs by Domain Count', fontsize=14, fontweight='bold')
            ax1.invert_yaxis()

            # Add value labels
            for i, bar in enumerate(bars1):
                width = bar.get_width()
                ax1.text(width, bar.get_y() + bar.get_height()/2,
                        f' {int(width):,}',
                        ha='left', va='center', fontsize=9)

            # Plot 2: IP count
            bars2 = ax2.barh(asn_labels, ip_counts, color='coral')
            ax2.set_xlabel('Number of IP Mappings', fontsize=12)
            ax2.set_ylabel('ASN', fontsize=12)
            ax2.set_title('Top ASNs by IP Mapping Count', fontsize=14, fontweight='bold')
            ax2.invert_yaxis()

            # Add value labels
            for i, bar in enumerate(bars2):
                width = bar.get_width()
                ax2.text(width, bar.get_y() + bar.get_height()/2,
                        f' {int(width):,}',
                        ha='left', va='center', fontsize=9)

            plt.tight_layout()

            # Save
            if output_path is None:
                output_path = self.output_dir / 'top_asns.png'
            plt.savefig(output_path, dpi=150, bbox_inches='tight')
            plt.close()

            logger.info(f"Saved top ASNs visualization: {output_path}")
            return str(output_path)

        except Exception as e:
            logger.error(f"Error creating top ASNs visualization: {e}")
            return ""

    def plot_asn_distribution(
        self,
        analytics_data: Dict[str, Any],
        output_path: Optional[str] = None
    ) -> str:
        """
        Create pie chart of ASN distribution.

        Args:
            analytics_data: Analytics data from ASNAnalytics
            output_path: Optional custom output path

        Returns:
            Path to saved visualization
        """
        try:
            import matplotlib.pyplot as plt
            import matplotlib
            matplotlib.use('Agg')
        except ImportError:
            logger.error("Visualization requires matplotlib: pip install matplotlib")
            return ""

        try:
            if 'top_asns' not in analytics_data:
                logger.error("No top_asns data in analytics")
                return ""

            top_asns = analytics_data['top_asns'][:10]
            if not top_asns:
                logger.warning("No ASN data to visualize")
                return ""

            # Prepare data
            labels = [f"AS{asn['asn']}" for asn in top_asns]
            sizes = [asn['ip_count'] for asn in top_asns]

            # Calculate "Others" category
            total_ips = analytics_data.get('total_ip_mappings', sum(sizes))
            others = total_ips - sum(sizes)
            if others > 0:
                labels.append('Others')
                sizes.append(others)

            # Create pie chart
            fig, ax = plt.subplots(figsize=(12, 8))

            colors = plt.cm.Set3.colors[:len(labels)]
            wedges, texts, autotexts = ax.pie(
                sizes,
                labels=labels,
                autopct='%1.1f%%',
                startangle=90,
                colors=colors,
                textprops={'fontsize': 10}
            )

            # Enhance autopct
            for autotext in autotexts:
                autotext.set_color('white')
                autotext.set_weight('bold')

            ax.set_title('ASN Distribution (by IP Mappings)', fontsize=14, fontweight='bold', pad=20)

            plt.tight_layout()

            # Save
            if output_path is None:
                output_path = self.output_dir / 'asn_distribution.png'
            plt.savefig(output_path, dpi=150, bbox_inches='tight')
            plt.close()

            logger.info(f"Saved ASN distribution visualization: {output_path}")
            return str(output_path)

        except Exception as e:
            logger.error(f"Error creating ASN distribution visualization: {e}")
            return ""

    def plot_asn_trends(
        self,
        trend_data: Dict[str, Any],
        output_path: Optional[str] = None
    ) -> str:
        """
        Create line chart of ASN trends over time.

        Args:
            trend_data: Trend data from ASNAnalytics.get_asn_trends()
            output_path: Optional custom output path

        Returns:
            Path to saved visualization
        """
        try:
            import matplotlib.pyplot as plt
            import matplotlib.dates as mdates
            import matplotlib
            matplotlib.use('Agg')
            from datetime import datetime
        except ImportError:
            logger.error("Visualization requires matplotlib: pip install matplotlib")
            return ""

        try:
            if 'trend_data' not in trend_data or not trend_data['trend_data']:
                logger.error("No trend data to visualize")
                return ""

            trends = trend_data['trend_data']

            # Parse dates
            dates = [datetime.fromisoformat(t['date'].replace('Z', '+00:00')) for t in trends]
            ip_counts = [t['ip_count'] for t in trends]
            domain_counts = [t['domain_count'] for t in trends]

            # Create figure with two y-axes
            fig, ax1 = plt.subplots(figsize=(12, 6))

            color1 = 'steelblue'
            ax1.set_xlabel('Date', fontsize=12)
            ax1.set_ylabel('IP Count', color=color1, fontsize=12)
            line1 = ax1.plot(dates, ip_counts, color=color1, linewidth=2, marker='o', label='IP Count')
            ax1.tick_params(axis='y', labelcolor=color1)
            ax1.grid(True, alpha=0.3)

            # Second y-axis
            ax2 = ax1.twinx()
            color2 = 'coral'
            ax2.set_ylabel('Domain Count', color=color2, fontsize=12)
            line2 = ax2.plot(dates, domain_counts, color=color2, linewidth=2, marker='s', label='Domain Count')
            ax2.tick_params(axis='y', labelcolor=color2)

            # Format x-axis
            ax1.xaxis.set_major_formatter(mdates.DateFormatter('%Y-%m-%d'))
            plt.setp(ax1.xaxis.get_majorticklabels(), rotation=45, ha='right')

            # Title
            asn = trend_data.get('asn', 'Unknown')
            ax1.set_title(f'AS{asn} Trend Analysis ({trend_data.get("period_days", "N/A")} days)',
                         fontsize=14, fontweight='bold')

            # Legend
            lines = line1 + line2
            labels = [l.get_label() for l in lines]
            ax1.legend(lines, labels, loc='upper left')

            plt.tight_layout()

            # Save
            if output_path is None:
                output_path = self.output_dir / f'asn_{asn}_trends.png'
            plt.savefig(output_path, dpi=150, bbox_inches='tight')
            plt.close()

            logger.info(f"Saved ASN trends visualization: {output_path}")
            return str(output_path)

        except Exception as e:
            logger.error(f"Error creating ASN trends visualization: {e}")
            return ""

    def plot_diversity_metrics(
        self,
        diversity_data: Dict[str, Any],
        output_path: Optional[str] = None
    ) -> str:
        """
        Create visualization of diversity metrics.

        Args:
            diversity_data: Diversity data from ASNAnalytics.get_asn_diversity_score()
            output_path: Optional custom output path

        Returns:
            Path to saved visualization
        """
        try:
            import matplotlib.pyplot as plt
            import matplotlib.patches as mpatches
            import matplotlib
            matplotlib.use('Agg')
        except ImportError:
            logger.error("Visualization requires matplotlib: pip install matplotlib")
            return ""

        try:
            # Create figure
            fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(14, 6))

            # Plot 1: Diversity Score gauge
            diversity_score = diversity_data.get('diversity_score', 0)

            # Create gauge background
            theta = [0, 120, 240, 360]
            radii = [10, 10, 10, 10]
            width = [120, 120, 120, 0]
            colors = ['#d9534f', '#f0ad4e', '#5cb85c']  # red, yellow, green

            bars = ax1.bar(theta[:3], radii[:3], width=width[:3], bottom=0,
                          color=colors, alpha=0.3, edgecolor='none')

            # Add score pointer
            score_angle = (diversity_score / 100) * 360
            ax1.plot([0, score_angle], [0, 8], color='black', linewidth=3)
            ax1.plot(score_angle, 8, 'o', color='black', markersize=12)

            # Configure plot
            ax1.set_theta_zero_location('N')
            ax1.set_theta_direction(-1)
            ax1.set_ylim(0, 10)
            ax1.set_yticks([])
            ax1.set_xticks([0, 90, 180, 270])
            ax1.set_xticklabels(['0', '25', '50', '75'])
            ax1.set_title(f'Diversity Score: {diversity_score:.1f}/100',
                         fontsize=14, fontweight='bold', pad=20)

            # Convert to polar
            ax1.remove()
            ax1 = fig.add_subplot(121, projection='polar')
            theta_rad = [t * 3.14159 / 180 for t in theta]
            bars = ax1.bar(theta_rad[:3], radii[:3], width=[w * 3.14159 / 180 for w in width[:3]],
                          bottom=0, color=colors, alpha=0.3, edgecolor='none')

            score_angle_rad = score_angle * 3.14159 / 180
            ax1.plot([0, score_angle_rad], [0, 8], color='black', linewidth=3)
            ax1.plot(score_angle_rad, 8, 'o', color='black', markersize=12)

            ax1.set_theta_zero_location('N')
            ax1.set_theta_direction(-1)
            ax1.set_ylim(0, 10)
            ax1.set_yticks([])
            ax1.set_xticks([0, 1.57, 3.14, 4.71])
            ax1.set_xticklabels(['0', '25', '50', '75'])
            ax1.set_title(f'Diversity Score: {diversity_score:.1f}/100',
                         fontsize=14, fontweight='bold', pad=20)

            # Plot 2: Metrics summary
            ax2.axis('off')

            metrics_text = f"""
ASN Diversity Metrics

Unique ASNs: {diversity_data.get('unique_asns', 0):,}
Total Mappings: {diversity_data.get('total_mappings', 0):,}

Shannon Entropy: {diversity_data.get('shannon_entropy', 0):.3f}
Diversity Score: {diversity_score:.2f}/100
Gini Coefficient: {diversity_data.get('gini_coefficient', 0):.3f}

Interpretation:
• Diversity: {diversity_data.get('interpretation', {}).get('diversity', 'N/A').upper()}
• Concentration: {diversity_data.get('interpretation', {}).get('concentration', 'N/A').upper()}
"""

            ax2.text(0.1, 0.5, metrics_text, fontsize=12, family='monospace',
                    verticalalignment='center', bbox=dict(boxstyle='round', facecolor='wheat', alpha=0.3))

            plt.tight_layout()

            # Save
            if output_path is None:
                output_path = self.output_dir / 'diversity_metrics.png'
            plt.savefig(output_path, dpi=150, bbox_inches='tight')
            plt.close()

            logger.info(f"Saved diversity metrics visualization: {output_path}")
            return str(output_path)

        except Exception as e:
            logger.error(f"Error creating diversity metrics visualization: {e}")
            return ""

    def create_interactive_dashboard(
        self,
        analytics_data: Dict[str, Any],
        output_path: Optional[str] = None
    ) -> str:
        """
        Create interactive HTML dashboard using Plotly.

        Args:
            analytics_data: Analytics data from ASNAnalytics
            output_path: Optional custom output path

        Returns:
            Path to saved HTML file
        """
        try:
            import plotly.graph_objects as go
            from plotly.subplots import make_subplots
        except ImportError:
            logger.error("Interactive dashboard requires plotly: pip install plotly")
            return ""

        try:
            if 'top_asns' not in analytics_data:
                logger.error("No ASN data for dashboard")
                return ""

            # Create subplots
            fig = make_subplots(
                rows=2, cols=2,
                subplot_titles=('Top ASNs by Domain Count', 'Top ASNs by IP Count',
                               'ASN Distribution', 'Metrics Summary'),
                specs=[[{"type": "bar"}, {"type": "bar"}],
                      [{"type": "pie"}, {"type": "table"}]]
            )

            top_asns = analytics_data['top_asns'][:15]

            # Plot 1: Domain count bar
            asn_labels = [f"AS{asn['asn']}" for asn in top_asns]
            domain_counts = [asn['domain_count'] for asn in top_asns]

            fig.add_trace(
                go.Bar(x=asn_labels, y=domain_counts, name='Domains', marker_color='steelblue'),
                row=1, col=1
            )

            # Plot 2: IP count bar
            ip_counts = [asn['ip_count'] for asn in top_asns]

            fig.add_trace(
                go.Bar(x=asn_labels, y=ip_counts, name='IPs', marker_color='coral'),
                row=1, col=2
            )

            # Plot 3: Pie chart
            pie_labels = [f"AS{asn['asn']}" for asn in analytics_data['top_asns'][:10]]
            pie_values = [asn['ip_count'] for asn in analytics_data['top_asns'][:10]]

            fig.add_trace(
                go.Pie(labels=pie_labels, values=pie_values, name='Distribution'),
                row=2, col=1
            )

            # Plot 4: Metrics table
            metrics_data = [
                ['Total ASNs', f"{analytics_data.get('total_unique_asns', 0):,}"],
                ['Total IPs', f"{analytics_data.get('total_ip_mappings', 0):,}"],
                ['Avg IPs/ASN', f"{analytics_data.get('avg_ips_per_asn', 0):.2f}"],
                ['Concentration', f"{analytics_data.get('concentration_ratio', 0):.2f}%"]
            ]

            fig.add_trace(
                go.Table(
                    header=dict(values=['Metric', 'Value'], fill_color='steelblue', font=dict(color='white')),
                    cells=dict(values=[[row[0] for row in metrics_data], [row[1] for row in metrics_data]],
                              fill_color='lavender')
                ),
                row=2, col=2
            )

            # Update layout
            fig.update_layout(
                title_text=f"ASN Analysis Dashboard - {analytics_data.get('scan_id', 'N/A')}",
                showlegend=False,
                height=900
            )

            # Save
            if output_path is None:
                output_path = self.output_dir / 'dashboard.html'
            fig.write_html(str(output_path))

            logger.info(f"Saved interactive dashboard: {output_path}")
            return str(output_path)

        except Exception as e:
            logger.error(f"Error creating interactive dashboard: {e}")
            return ""
