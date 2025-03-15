# gnuplot script

set datafile separator ","
set terminal pngcairo size 1600,900 enhanced font "JetBrainsMono,14"
set output "bench.1m-iter.png"

# Title and Labels
set title "Hash Algorithm Performance (1M iterations)" font ",16"
set xlabel "Algorithm" font ",14"
set ylabel "Time (µs)" font ",14"

# Grid and Borders
set grid ytics lc rgb "#dddddd"
set border 3 lc rgb "#aaaaaa"

# Color Gradient for Bars
set style fill solid 1.0 border -1
set boxwidth 0.6

# Rotate x-axis labels for better readability
set xtics rotate by -45 font ",12"

# Define colors for the bars
set style line 1 lc rgb "#1f77b4"  # Blue
set style line 2 lc rgb "#ff7f0e"  # Orange
set style line 3 lc rgb "#2ca02c"  # Green
set style line 4 lc rgb "#d62728"  # Red
set style line 5 lc rgb "#9467bd"  # Purple

# Use alternating colors
plot "bench.csv" using 2:xtic(1) title "Time (µs)" with boxes ls 4
