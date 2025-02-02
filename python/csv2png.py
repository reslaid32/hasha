import pandas as pd
import matplotlib.pyplot as plt
import numpy as np
import sys
import getopt

def plot_benchmark(input_csv, output_png):
    # Load CSV data into a pandas DataFrame
    df = pd.read_csv(input_csv)
    
    # Convert columns to numeric values (handle errors)
    df['Total Time (s)'] = pd.to_numeric(df['Total Time (s)'], errors='coerce')
    df['Avg Time per Iteration (us)'] = pd.to_numeric(df['Avg Time per Iteration (us)'], errors='coerce')
    
    # Drop missing values
    df = df.dropna()
    
    # Set up the figure
    fig, ax = plt.subplots(figsize=(12, 7))
    
    # Define colors
    openSSL_color = '#FF6F61'  # Coral Red for OpenSSL
    hasha_color = '#4C72B0'    # Cobalt Blue for Hasha
    
    # Loop through algorithms and create bars
    bars = []
    for index, row in df.iterrows():
        color = openSSL_color if 'openssl' in row['Algorithm'].lower() else hasha_color
        bar1 = ax.bar(index - 0.15, row['Total Time (s)'], 0.3, color=color, edgecolor='black', linewidth=1.2, zorder=3)
        bar2 = ax.bar(index + 0.15, row['Avg Time per Iteration (us)'], 0.3, color=color, edgecolor='black', linewidth=1.2, zorder=3)
        bars.append(bar1)
        bars.append(bar2)
    
    # Customize plot appearance
    ax.set_title('Hash Algorithm Benchmark Comparison', fontsize=18, fontweight='bold', color='#333333')
    ax.set_xlabel('Hash Algorithm', fontsize=14, color='#333333')
    ax.set_ylabel('Time (us)', fontsize=14, color='#333333')
    ax.set_xticks(np.arange(len(df)))
    ax.set_xticklabels(df['Algorithm'], rotation=45, ha='right', fontsize=12, color='#333333')
    ax.set_ylim(0, df[['Total Time (s)', 'Avg Time per Iteration (us)']].max().max() * 1.1)
    ax.grid(True, linestyle='--', alpha=0.6, zorder=0)
    
    # Legend
    ax.legend(bars[::2], df['Algorithm'], loc='upper left', bbox_to_anchor=(1.05, 1), title="Algorithms", fontsize=12)
    
    # Add color scheme note
    ax.text(0.5, 0.98, "Red: OpenSSL, Blue: Hasha", ha='center', va='center', transform=ax.transAxes, fontsize=13, fontweight='bold', color='black', backgroundcolor='white')
    
    # Background styling
    fig.patch.set_facecolor('#f7f7f7')
    ax.set_facecolor('#ffffff')
    
    # Save plot
    plt.savefig(output_png, dpi=300, bbox_inches='tight')
    
    # Show the plot
    plt.show()

def main(argv):
    input_csv = ''
    output_png = ''
    try:
        opts, args = getopt.getopt(argv, "hi:o:", ["input=", "output="])
    except getopt.GetoptError:
        print('Usage: script.py -i <input_csv> -o <output_png>')
        sys.exit(2)
    for opt, arg in opts:
        if opt == '-h':
            print('Usage: script.py -i <input_csv> -o <output_png>')
            sys.exit()
        elif opt in ("-i", "--input"):
            input_csv = arg
        elif opt in ("-o", "--output"):
            output_png = arg
    if not input_csv or not output_png:
        print('Missing required arguments. Usage: script.py -i <input_csv> -o <output_png>')
        sys.exit(2)
    plot_benchmark(input_csv, output_png)

if __name__ == "__main__":
    main(sys.argv[1:])
