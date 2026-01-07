# Railway Deployment Guide for Balancing Bolts

This guide will walk you through deploying your Balancing Bolts apartment inventory manager to Railway.

## Prerequisites

- Railway account (sign up at https://railway.app)
- Your GitHub repository connected to Railway
- Git installed on your computer

## Step-by-Step Deployment Instructions

### Step 1: Commit the Configuration Files

First, commit the new Railway configuration files to your repository:

```bash
cd "Balancing Bolts"
git add railway.json nixpacks.toml .railwayignore RAILWAY_DEPLOYMENT.md
git commit -m "Add Railway deployment configuration"
git push origin main
```

### Step 2: Set Up Your Railway Project

1. **Go to Railway Dashboard**
   - Visit https://railway.app/dashboard
   - Log in to your account

2. **Create New Project**
   - Click "New Project"
   - Select "Deploy from GitHub repo"
   - Choose your `Balancing-Bolts` repository
   - Railway will automatically detect it as a Python project

3. **Configure the Service**
   - Railway will use the `railway.json` and `nixpacks.toml` files we created
   - The build should start automatically

### Step 3: Configure Environment Variables (Optional)

If you want to use AI features or ResMan integration, add these environment variables in Railway:

1. Click on your service in Railway
2. Go to the "Variables" tab
3. Add any of these (all are optional):

   ```
   OPENAI_API_KEY=sk-your-key-here          # For AI assistant features
   RESMAN_CLIENT_ID=your-client-id          # For ResMan OAuth
   RESMAN_CLIENT_SECRET=your-secret         # For ResMan OAuth
   RESMAN_REDIRECT_URI=your-callback-url    # For ResMan OAuth
   LOG_LEVEL=INFO                           # Set to DEBUG for more logs
   ```

   **Note:** These are all optional. The app works fine without them - you just won't have AI features or ResMan integration.

### Step 4: Deploy and Get Your URL

1. **Wait for Deployment**
   - Railway will build and deploy your app (takes 2-3 minutes)
   - Watch the build logs in the "Deployments" tab

2. **Get Your Public URL**
   - Go to the "Settings" tab
   - Scroll to "Environment" section
   - Click "Generate Domain" to get a public URL
   - Your app will be live at something like: `https://balancing-bolts-production.up.railway.app`

3. **Access Your App**
   - Visit your Railway URL
   - You should see the Balancing Bolts login page
   - Sign up for a new account (first user becomes admin)

### Step 5: Create Your First Admin User

When you first access your deployed app:

1. Click "Sign up here" on the login page
2. Enter your email and password
3. You'll be automatically logged in
4. Start managing your properties and inventory!

## Important Notes

### Database Persistence

- Railway uses **ephemeral storage** by default, meaning your database will reset on each deployment
- To persist your data between deployments, you need to add a **PostgreSQL database**:

  1. In Railway dashboard, click "+ New" → "Database" → "Add PostgreSQL"
  2. Railway will automatically add a `DATABASE_URL` environment variable
  3. Update your `backend/database.py` to use PostgreSQL instead of SQLite (if needed)

### SQLite vs PostgreSQL

For now, your app uses SQLite which is fine for testing. For production use with permanent data storage:

**Option A: Keep SQLite with Volume (Simpler)**
- In Railway, go to Settings → Volumes
- Add a volume mounted at `/app/backend`
- This makes your SQLite database persist between deployments

**Option B: Upgrade to PostgreSQL (Recommended for Production)**
- Better for multi-user access
- Automatic backups
- Scales better
- Let me know if you want help with this upgrade!

## Troubleshooting

### Build Fails
- Check the build logs in Railway
- Make sure all files are committed and pushed to GitHub
- Verify `requirements.txt` has all dependencies

### App Won't Start
- Check the deployment logs
- Make sure the start command is correct: `uvicorn backend.main:app --host 0.0.0.0 --port $PORT`
- Verify Python version is 3.11+

### Can't Access the URL
- Make sure you generated a domain in Settings
- Check if the deployment is "Active" (green indicator)
- Look at the logs for any error messages

## Automatic Deployments

Railway automatically deploys when you push to your GitHub repository:

1. Make code changes locally
2. Commit: `git commit -m "Your changes"`
3. Push: `git push origin main`
4. Railway automatically rebuilds and deploys!

## Cost

- Railway offers $5/month free credit
- Your app should stay within free tier for small usage
- Monitor usage in Railway dashboard

## Next Steps After Deployment

1. **Set up admin account** - First signup becomes admin
2. **Create properties** - Add your 9 apartment properties
3. **Import invoices** - Upload CSV files with invoice data
4. **Invite team members** - Have them sign up and assign roles
5. **Set up persistent storage** - Add a volume or PostgreSQL database

## Need Help?

- Railway Documentation: https://docs.railway.app
- Railway Discord: https://discord.gg/railway
- Check logs in Railway dashboard for error messages

---

**Your app should now be accessible from anywhere in the world!** 🎉
