package com.repoguard.scanner;

import com.github.javaparser.StaticJavaParser;
import com.github.javaparser.ast.CompilationUnit;
import com.github.javaparser.ast.expr.BinaryExpr;
import com.github.javaparser.ast.expr.MethodCallExpr;
import com.github.javaparser.ast.expr.StringLiteralExpr;
import com.github.javaparser.ast.visitor.VoidVisitorAdapter;
import com.repoguard.model.Severity;
import com.repoguard.model.Vulnerability;
import org.springframework.stereotype.Component;

import java.io.File;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

@Component
public class XSSScanner {

    public List<Vulnerability> scan(List<File> javaFiles) {
        List<Vulnerability> vulnerabilities = new ArrayList<>();

        for (File file : javaFiles) {
            try {
                CompilationUnit cu = StaticJavaParser.parse(file);
                Set<Integer> flaggedLines = new HashSet<>();

                cu.accept(new VoidVisitorAdapter<Void>() {

                    @Override
                    public void visit(MethodCallExpr n, Void arg) {
                        super.visit(n, arg);
                        int line = n.getBegin().isPresent() ? n.getBegin().get().line : 0;
                        String methodName = n.getNameAsString();

                        if ((methodName.equals("print") || methodName.equals("println") || methodName.equals("write"))
                                && n.getScope().isPresent() && !flaggedLines.contains(line)) {
                            String scopeStr = n.getScope().get().toString();
                            if (scopeStr.contains("getWriter") || scopeStr.equals("out") || scopeStr.equals("response")) {
                                if (n.getArguments().isNonEmpty() && !(n.getArgument(0) instanceof StringLiteralExpr)) {
                                    flaggedLines.add(line);
                                    vulnerabilities.add(new Vulnerability(
                                            "XSS", Severity.HIGH, file.getName(), line,
                                            "AST Detection: Dynamic input written directly to HTTP response.",
                                            "Escape user input using OWASP Java Encoder or HtmlUtils.htmlEscape()."
                                    ));
                                }
                            }
                        }
                    }

                    @Override
                    public void visit(BinaryExpr n, Void arg) {
                        int line = n.getBegin().isPresent() ? n.getBegin().get().line : 0;
                        if (n.getOperator() == BinaryExpr.Operator.PLUS && !flaggedLines.contains(line)) {
                            boolean hasHtml = n.findAll(StringLiteralExpr.class).stream()
                                    .map(StringLiteralExpr::getValue)
                                    .anyMatch(val -> val.matches(".*<[a-zA-Z]+.*>.*"));

                            if (hasHtml && !(n.getLeft() instanceof StringLiteralExpr && n.getRight() instanceof StringLiteralExpr)) {
                                flaggedLines.add(line);
                                vulnerabilities.add(new Vulnerability(
                                        "XSS", Severity.MEDIUM, file.getName(), line,
                                        "AST Detection: HTML built via string concatenation with variables.",
                                        "Use a templating engine (Thymeleaf, FreeMarker) or escape input."
                                ));
                            }
                        }
                        // Manually traverse children to avoid duplicate visits
                        n.getLeft().accept(this, arg);
                        n.getRight().accept(this, arg);
                    }
                }, null);

            } catch (Exception e) {
                System.out.println("Error parsing file with JavaParser: " + file.getName());
            }
        }

        return vulnerabilities;
    }
}
