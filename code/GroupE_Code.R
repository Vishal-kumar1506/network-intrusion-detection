
# ============================================================
# MATH 167R Spring 2026 - Group E
# Network Intrusion Detection Using CIC-IDS-2017
# Members: Vishal Kumar, Avanti Gupta, Shivangi Manel
# ============================================================

# ---- SECTION 1: Load Libraries ----
library(data.table)
library(tidyverse)
library(caret)
library(randomForest)
library(xgboost)
library(corrplot)
library(pROC)
library(gridExtra)
library(rmarkdown)

# ---- SECTION 2: Load Data ----
path <- "~/Downloads/Network Intrusion dataset(CIC-IDS- 2017)/"
files <- list.files(path, pattern = "*.csv", full.names = TRUE)

df <- rbindlist(lapply(files, function(f) {
  cat("Loading:", basename(f), "
")
  fread(f, stringsAsFactors = FALSE)
}), fill = TRUE)

cat("Total rows:", nrow(df), "
")
cat("Total columns:", ncol(df), "
")

# ---- SECTION 3: Data Cleaning ----
# Clean column names
names(df) <- trimws(names(df))

# Check label distribution
cat("=== Label Distribution ===
")
print(table(df$Label))

# Replace Inf and -Inf with NA
df[df == Inf | df == -Inf] <- NA

# Check and remove missing values
na_counts <- colSums(is.na(df))
cat("Columns with missing values:
")
print(na_counts[na_counts > 0])
df <- na.omit(df)
cat("Rows after cleaning:", nrow(df), "
")

# Convert Label to factor
df$Label <- as.factor(trimws(df$Label))

# ---- SECTION 4: EDA Visualizations ----
# Plot 1: Class Distribution
label_counts <- as.data.frame(table(df$Label))
names(label_counts) <- c("Attack_Type", "Count")

ggplot(label_counts, aes(x = reorder(Attack_Type, -Count),
                          y = Count, fill = Attack_Type)) +
  geom_bar(stat = "identity") +
  scale_y_log10() +
  theme_minimal() +
  theme(axis.text.x = element_text(angle = 45, hjust = 1),
        legend.position = "none") +
  labs(title = "Class Distribution (Log Scale)",
       x = "Attack Type", y = "Count (log scale)")

# Plot 2: Flow Duration Density
names(df) <- make.unique(names(df))
top5 <- c("BENIGN", "DoS Hulk", "PortScan", "DDoS", "FTP-Patator")

df %>%
  dplyr::filter(Label %in% top5) %>%
  ggplot(aes(x = `Flow Duration`, fill = Label)) +
  geom_density(alpha = 0.5) +
  scale_x_log10() +
  theme_minimal() +
  labs(title = "Flow Duration Distribution by Attack Type",
       x = "Flow Duration (log scale)", y = "Density")

# Plot 3: Flow Bytes/s Boxplot
df %>%
  dplyr::filter(Label %in% top5) %>%
  ggplot(aes(x = Label, y = `Flow Bytes/s`, fill = Label)) +
  geom_boxplot(outlier.size = 0.5, outlier.alpha = 0.3) +
  scale_y_log10() +
  theme_minimal() +
  theme(axis.text.x = element_text(angle = 45, hjust = 1),
        legend.position = "none") +
  labs(title = "Flow Bytes/s by Attack Type",
       x = "Attack Type", y = "Flow Bytes/s (log scale)")

# Plot 4: Correlation Heatmap
numeric_cols <- df %>%
  dplyr::select(where(is.numeric)) %>%
  dplyr::select(1:20)
cor_matrix <- cor(numeric_cols, use = "complete.obs")
corrplot(cor_matrix, method = "color", type = "upper",
         tl.cex = 0.6, tl.col = "black",
         title = "Feature Correlation Heatmap (First 20 Features)",
         mar = c(0,0,1,0))

# ---- SECTION 5: Preprocessing ----
# Remove zero variance columns
numeric_df <- df %>% dplyr::select(where(is.numeric))
zero_var <- names(numeric_df)[sapply(numeric_df, function(x) var(x, na.rm = TRUE) == 0)]
cat("Removing zero variance columns:", length(zero_var), "
")
df <- df %>% dplyr::select(-all_of(zero_var))

# Remove highly correlated features
numeric_df <- df %>% dplyr::select(where(is.numeric))
cor_matrix_full <- cor(numeric_df, use = "complete.obs")
high_cor <- findCorrelation(cor_matrix_full, cutoff = 0.95)
cat("Removing", length(high_cor), "highly correlated features
")
df <- df %>% dplyr::select(-all_of(names(numeric_df)[high_cor]))
cat("Remaining columns:", ncol(df), "
")

# Fix column names
names(df) <- make.names(trimws(names(df)))

# Stratified 10% sample
set.seed(42)
df_sample <- df %>%
  group_by(Label) %>%
  slice_sample(prop = 0.10) %>%
  ungroup()

# Remove extremely rare classes
df_sample <- df_sample %>%
  dplyr::filter(!Label %in% c("Heartbleed", "Web.Attack...Sql.Injection"))
df_sample$Label <- droplevels(df_sample$Label)
cat("Sample size:", nrow(df_sample), "
")

# Descriptive Statistics
key_features <- c("Flow.Bytes.s", "Packet.Length.Std",
                  "Average.Packet.Size", "Fwd.Packet.Length.Mean",
                  "Bwd.Packet.Length.Std", "Flow.IAT.Mean")

desc_table <- df_sample %>%
  dplyr::select(all_of(key_features)) %>%
  summarise(across(everything(), list(
    Mean   = ~round(mean(., na.rm=TRUE), 2),
    Median = ~round(median(., na.rm=TRUE), 2),
    SD     = ~round(sd(., na.rm=TRUE), 2),
    Min    = ~round(min(., na.rm=TRUE), 2),
    Max    = ~round(max(., na.rm=TRUE), 2)
  ))) %>%
  tidyr::pivot_longer(everything(),
    names_to = c("Feature", "Stat"), names_sep = "_") %>%
  tidyr::pivot_wider(names_from = Stat, values_from = value)
print(desc_table)

# Normalize
preproc <- preProcess(df_sample %>% dplyr::select(where(is.numeric)),
                      method = c("range"))
df_scaled <- predict(preproc, df_sample)

# Train/Test Split
set.seed(42)
train_idx <- createDataPartition(df_scaled$Label, p = 0.8, list = FALSE)
train_df <- df_scaled[train_idx, ]
test_df  <- df_scaled[-train_idx, ]
cat("Train rows:", nrow(train_df), "
")
cat("Test rows:", nrow(test_df), "
")

# ---- SECTION 6: Random Forest Model ----
set.seed(42)
cat("Training Random Forest...
")
rf_model <- randomForest(Label ~ .,
                         data = train_df,
                         ntree = 500,
                         mtry = 5,
                         importance = TRUE)
cat("Done!
")
print(rf_model)

# Evaluate Random Forest
rf_pred <- predict(rf_model, test_df)
conf_matrix <- confusionMatrix(rf_pred, test_df$Label)
f1_scores <- conf_matrix$byClass[, "F1"]
print(round(f1_scores, 3))

# Feature Importance Plot
importance_df <- as.data.frame(importance(rf_model))
importance_df$Feature <- rownames(importance_df)

importance_df %>%
  arrange(desc(MeanDecreaseGini)) %>%
  head(20) %>%
  ggplot(aes(x = reorder(Feature, MeanDecreaseGini),
             y = MeanDecreaseGini, fill = MeanDecreaseGini)) +
  geom_bar(stat = "identity") + coord_flip() +
  scale_fill_gradient(low = "lightblue", high = "darkblue") +
  theme_minimal() + theme(legend.position = "none") +
  labs(title = "Top 20 Most Important Features (Random Forest)",
       x = "Feature", y = "Mean Decrease Gini")

# ---- SECTION 7: XGBoost Model ----
train_labels <- as.numeric(train_df$Label) - 1
test_labels  <- as.numeric(test_df$Label) - 1

train_matrix <- xgb.DMatrix(
  data  = as.matrix(train_df %>% dplyr::select(where(is.numeric))),
  label = train_labels)
test_matrix <- xgb.DMatrix(
  data  = as.matrix(test_df %>% dplyr::select(where(is.numeric))),
  label = test_labels)

set.seed(42)
cat("Training XGBoost...
")
xgb_model <- xgb.train(
  params = list(
    objective    = "multi:softmax",
    num_class    = length(unique(train_labels)),
    max_depth    = 6,
    learning_rate = 0.3,
    eval_metric  = "merror"),
  data    = train_matrix,
  nrounds = 100,
  evals   = list(train = train_matrix),
  verbose = 1)
cat("Done!
")

# Evaluate XGBoost
xgb_pred_num <- predict(xgb_model, test_matrix)
label_levels <- levels(train_df$Label)
xgb_pred <- factor(label_levels[xgb_pred_num + 1], levels = label_levels)
test_labels_factor <- factor(label_levels[test_labels + 1], levels = label_levels)
xgb_conf <- confusionMatrix(xgb_pred, test_labels_factor)
xgb_f1 <- xgb_conf$byClass[, "F1"]

# F1 Comparison Plot
comparison <- data.frame(
  Class = gsub("Class: ", "", names(xgb_f1)),
  RandomForest = round(f1_scores, 3),
  XGBoost = round(xgb_f1, 3))
print(comparison)

comparison %>%
  tidyr::pivot_longer(cols = c(RandomForest, XGBoost),
                      names_to = "Model", values_to = "F1") %>%
  dplyr::filter(!is.na(F1)) %>%
  ggplot(aes(x = Class, y = F1, fill = Model)) +
  geom_bar(stat = "identity", position = "dodge") +
  coord_flip() + theme_minimal() +
  labs(title = "F1 Score Comparison: Random Forest vs XGBoost",
       x = "Attack Class", y = "F1 Score") +
  scale_fill_manual(values = c("RandomForest" = "steelblue",
                                "XGBoost" = "darkorange"))

# ---- SECTION 8: ROC Curve ----
rf_prob <- predict(rf_model, test_df, type = "prob")[, "BENIGN"]
true_binary <- ifelse(test_df$Label == "BENIGN", 1, 0)
rf_roc <- roc(true_binary, rf_prob, quiet = TRUE)

plot(rf_roc, col = "steelblue", lwd = 2,
     main = "ROC Curve: BENIGN vs Attack Detection")
legend("bottomright",
       legend = c(paste("Random Forest AUC =", round(auc(rf_roc), 4))),
       col = "steelblue", lwd = 2)

# ---- SECTION 9: Render Final Report ----
render("GroupE_Report.Rmd")
cat("All done! Report saved as GroupE_Report.html
")

