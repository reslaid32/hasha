set datafile separator ","
set terminal pngcairo size 1600,900 enhanced font "JetBrainsMono,14"
set output "bench.per-iter.png"

# Title and Labels
set title "Hash Algorithm Performance (Per Iteration)" font ",16"
set xlabel "Algorithm" font ",14"
set ylabel "Time per Iteration (µs)" font ",14"

# Grid and Borders
set grid ytics lc rgb "#dddddd"
set border 3 lc rgb "#aaaaaa"

# Bar Appearance
set style fill solid 1.0 border -1
set boxwidth 0.6

# Rotate x-axis labels for better readability
set xtics rotate by -45 font ",12"

# Define bar color
set style line 1 lc rgb "#ff7f0e"  # Orange for avg time per iteration

# Plot only Avg Time per Iteration (column 4)
plot "bench.csv" using 4:xtic(1) title "Avg per Iteration (µs)" with boxes ls 1
