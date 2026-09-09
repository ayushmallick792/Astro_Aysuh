import { NextRequest, NextResponse } from "next/server";
import crypto from "crypto";
import Order from "@/models/Order";
import User from "@/models/User";

// IMPORTANT: Razorpay signs the RAW request body. Next.js App Router route
// handlers give you a parsed body by default, so we must read the raw text
// first and verify against that exact string — not JSON.stringify(body).

export async function POST(req: NextRequest) {
  try {
    const rawBody = await req.text();
    const signature = req.headers.get("x-razorpay-signature");

    const webhookSecret = process.env.RAZORPAY_WEBHOOK_SECRET;

    if (!webhookSecret) {
      console.error("RAZORPAY_WEBHOOK_SECRET is not configured");
      return NextResponse.json({ success: false }, { status: 500 });
    }

    if (!signature) {
      return NextResponse.json({ success: false, message: "Missing signature" }, { status: 400 });
    }

    // -----------------------------
    // 1. Verify the webhook signature
    // -----------------------------
    const expectedSignature = crypto
      .createHmac("sha256", webhookSecret)
      .update(rawBody)
      .digest("hex");

    const expectedBuffer = Buffer.from(expectedSignature, "hex");
    const receivedBuffer = Buffer.from(signature, "hex");

    if (
      expectedBuffer.length !== receivedBuffer.length ||
      !crypto.timingSafeEqual(expectedBuffer, receivedBuffer)
    ) {
      console.warn("Razorpay webhook: invalid signature");
      return NextResponse.json({ success: false, message: "Invalid signature" }, { status: 400 });
    }

    const event = JSON.parse(rawBody);

    // -----------------------------
    // 2. Only act on the events that mean "money received"
    // -----------------------------
    if (event.event === "payment.captured" || event.event === "order.paid") {
      const payment = event.payload?.payment?.entity;
      const razorpayOrderId: string | undefined = payment?.order_id ?? event.payload?.order?.entity?.id;
      const razorpayPaymentId: string | undefined = payment?.id;

      if (!razorpayOrderId) {
        return NextResponse.json({ success: true }); // nothing to do, ack anyway
      }

      const dbOrder = await Order.findOne({ razorpay_orderId: razorpayOrderId });

      if (!dbOrder) {
        console.warn(`Webhook: order ${razorpayOrderId} not found in DB`);
        return NextResponse.json({ success: true }); // ack so Razorpay stops retrying
      }

      // Idempotency — webhooks can be delivered more than once
      if (dbOrder.paymentStatus !== "paid") {
        dbOrder.paymentStatus = "paid";
        dbOrder.status = "completed";
        if (razorpayPaymentId) dbOrder.razorpay_PaymentId = razorpayPaymentId;
        await dbOrder.save();

        await User.updateOne(
          { _id: dbOrder.userId },
          { $addToSet: { books: dbOrder.bookId } }
        );
      }
    }

    // -----------------------------
    // 3. Always return 200 quickly so Razorpay doesn't keep retrying
    // -----------------------------
    return NextResponse.json({ success: true });
  } catch (error) {
    console.error("Razorpay webhook error:", error);
    // Still return 200-ish behavior deliberately avoided here: a genuine
    // processing error should surface as 500 so Razorpay retries delivery.
    return NextResponse.json({ success: false }, { status: 500 });
  }
}