
async function startCheckout(competition_id, quantity) {
  try {
    const res = await fetch("/api/checkout", {
      method: "POST",
      headers: {"Content-Type":"application/json"},
      body: JSON.stringify({ competition_id, quantity })
    });
    const data = await res.json();
    if (!res.ok) return alert(data.error || "Checkout failed");
    window.location.href = data.url;
  } catch (e) {
    alert("Checkout error");
    console.error(e);
  }
}
