<script setup lang="ts">
import { ref, onMounted, onUnmounted, watch } from 'vue';
import Chart from 'chart.js/auto';
import { readTheme } from './chartTheme';

const props = withDefaults(
  defineProps<{
    labels: string[];
    values: number[];
    yLabel?: string;
  }>(),
  { yLabel: undefined }
);

const canvas = ref<HTMLCanvasElement | null>(null);
let instance: InstanceType<typeof Chart> | null = null;

function build() {
  if (!canvas.value) return;
  const theme = readTheme();
  instance?.destroy();
  instance = new Chart(canvas.value, {
    type: 'line',
    data: {
      labels: props.labels,
      datasets: [{
        data: props.values,
        borderColor: theme.accentStrong,
        backgroundColor: `${theme.accentStrong}20`,
        fill: true,
        tension: 0.3,
        pointRadius: 0,
      }],
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      plugins: { legend: { display: false } },
      scales: {
        x: {
          ticks: { color: theme.axisLabel, font: { size: 10 } },
          grid: { color: theme.grid },
        },
        y: {
          ticks: { color: theme.axisLabel, font: { size: 10 } },
          grid: { color: theme.grid },
        },
      },
    },
  });
}

onMounted(build);
watch(() => [props.labels, props.values], build, { deep: true });
onUnmounted(() => instance?.destroy());
</script>

<template>
  <div class="t-chart">
    <canvas ref="canvas" />
  </div>
</template>

<style scoped>
.t-chart {
  position: relative;
  height: 180px;
}
</style>
