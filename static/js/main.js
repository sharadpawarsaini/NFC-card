// small helpers
document.addEventListener('DOMContentLoaded', () => {
  // enable copy for the public url input if exists
  const publicUrlInput = document.querySelector('input[readonly]');
  if (publicUrlInput) {
    publicUrlInput.addEventListener('click', () => {
      publicUrlInput.select();
      document.execCommand('copy');
      alert('Public link copied to clipboard');
    });
  }
});
