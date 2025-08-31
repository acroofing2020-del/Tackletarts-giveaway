// public/js/payment.js

// Load Stripe with your publishable key (set in Render Environment Variables)
const stripe = Stripe(STRIPE_PUBLISHABLE_KEY); // Replace if you don’t inject dynamically

document.addEventListener("DOMContentLoaded", () => {
  const checkoutButton = document.getElementById("checkout");

  if (!checkoutButton) return;

  checkoutButton.addEventListener("click", async () => {
    const quantity = document.getElementById("ticketQuantity").value;

    try {
      const res = await fetch("/api/create-checkout-session", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ quantity })
      });

      const session = await res.json();

      if (session.id) {
        await stripe.redirectToCheckout({ sessionId: session.id });
      } else {
        alert("⚠️ Could not start checkout, please try again.");
      }
    } catch (err) {
      console.error("Stripe checkout error:", err);
      alert("❌ Payment failed, please try again.");
    }
  });
});
